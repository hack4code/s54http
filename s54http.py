#! /bin/env python


import logging
import struct

from twisted.internet import reactor, protocol
from twisted.names import client, dns

from utils import daemon, mk_pid_file, parse_args, \
    ssl_ctx_factory, dns_cache, init_logger

logger = logging.getLogger(__name__)

config = {'daemon': False,
          'port': 6666,
          'ca': 'keys/ca.crt',
          'key': 'keys/s54http.key',
          'cert': 'keys/s54http.crt',
          'pidfile': 's54http.pid',
          'logfile': 's54http.log',
          'loglevel': 'INFO'}


def verify_tun(conn, x509, errno, errdepth, ok):
    if not ok:
        cn = x509.get_subject().commonName
        logger.error('ssl verify failed: errno=%d cn=%s',
                     errno,
                     cn)
    return ok


class remote_protocol(protocol.Protocol):
    def connectionMade(self):
        self.local_sock.remoteConnectionMade(self)

    def dataReceived(self, data):
        self.local_sock.transport.write(data)


class remote_factory(protocol.ClientFactory):
    def __init__(self, sock, host=''):
        self.protocol = remote_protocol
        self.local_sock = sock
        self.remote_host = host

    def buildProtocol(self, addr):
        p = protocol.ClientFactory.buildProtocol(self,
                                                 addr)
        p.local_sock = self.local_sock
        return p

    def clientConnectionFailed(self, connector, reason):
        logger.error('connect %s failed: %s',
                     self.remote_host,
                     reason.getErrorMessage())
        self.local_sock.sendConnectReply(5)
        self.local_sock.transport.loseConnection()

    def clientConnectionLost(self, connector, reason):
        logger.info('connetion to %s closed: %s',
                    self.remote_host,
                    reason.getErrorMessage())
        self.local_sock.transport.loseConnection()


ncache = dns_cache(1000)


class socks5_protocol(protocol.Protocol):
    def connectionMade(self):
        self.state = 'waitHello'
        self.buf = b''
        self.remote_factory = None

    def connectionLost(self, reason=None):
        logger.info('tunnel connetion closed')
        if self.remote_factory:
            logger.info('close remote connection')
            self.remote_factory.stopFactory()

    def dataReceived(self, data):
        method = getattr(self,
                         self.state)
        method(data)

    def waitHello(self, data):
        self.buf += data
        if len(self.buf) < 2:
            return
        ver, nmethods = struct.unpack('!BB', self.buf[:2])
        logger.info('version=%d, nmethods=%d',
                    ver,
                    nmethods)
        if ver != 5:
            logger.error('socks %d not supported',
                         ver)
            self.sendHelloReply(0xFF)
            self.transport.loseConnection()
            return
        if nmethods < 1:
            logger.error('no method')
            self.sendHelloReply(0xFF)
            self.transport.loseConnection()
            return
        if len(self.buf) < nmethods + 2:
            return
        for method in self.buf[2:2+nmethods]:
            if method == 0:
                self.buf = b''
                self.state = 'waitConnectRemote'
                logger.info('state: waitConnectRemote')
                self.sendHelloReply(0)
                return
        self.sendHelloReply(0xFF)
        self.transport.loseConnection()

    def waitConnectRemote(self, data):
        self.buf += data
        if len(self.buf) < 4:
            return
        ver, cmd, rsv, atyp = struct.unpack('!BBBB',
                                            data[:4])
        if ver != 5 or rsv != 0:
            logger.error('ver: %d rsv: %d',
                         ver,
                         rsv)
            self.transport.loseConnection()
            return
        if cmd == 1:
            if atyp == 1:
                if len(self.buf) < 10:
                    return
                b1, b2, b3, b4 = struct.unpack('!BBBB',
                                               self.buf[4:8])
                host = '{}.{}.{}.{}'.format(b1,
                                            b2,
                                            b3,
                                            b4)
                port, = struct.unpack('!H',
                                      self.buf[8:10])
                self.buf = b''
                self.state = 'waitRemoteConnection'
                logger.info('state: waitRemoteConnection')
                self.connectRemote(host,
                                   port)
                logger.info('connect %s:%d',
                            host,
                            port)
                return
            elif atyp == 3:
                if len(self.buf) < 5:
                    return
                nlen, = struct.unpack('!B',
                                      self.buf[4:5])
                if len(self.buf) < 5 + nlen + 2:
                    return
                host = self.buf[5:5+nlen].decode('utf-8')
                port, = struct.unpack('!H',
                                      self.buf[5+nlen:7+nlen])
                self.buf = b''

                if host in ncache:
                    self.connectRemote(ncache[host],
                                       port)
                    logger.info('connect %s:%d',
                                host,
                                port)
                    self.state = 'waitRemoteConnection'
                    logger.info('state: waitRemoteConnection')
                    return

                d = self.R.lookupAddress(host)

                def resolve_ok(records, host, port):
                    answers, *_ = records
                    for a in answers:
                        if a.type == dns.A:
                            addr = a.payload.dottedQuad()
                            ncache[host] = addr
                            self.connectRemote(addr,
                                               port)
                            logger.info('connecting %s:%d',
                                        host,
                                        port)
                            self.state = 'waitRemoteConnection'
                            logger.info('state: waitRemoteConnection')
                            break
                    else:
                        logger.error('%s dns failed',
                                     host)
                        self.sendConnectReply(5)
                        self.transport.loseConnection()

                d.addCallback(resolve_ok, host, port)

                def resolve_err(res):
                    logger.error('%s dns error',
                                 res)
                    self.sendConnectReply(5)
                    self.transport.loseConnection()

                d.addErrback(resolve_err)
                self.state = 'waitNameRes'
                logger.info('state: waitNameResolve')
                return
            else:
                logger.error('type %d',
                             atyp)
                self.transport.loseConnection()
                return
        else:
            logger.error('command %d not supported',
                         cmd)
            self.transport.loseConnection()

    def waitNameResolve(self, data):
        logger.error('recv data when name resolving')

    def waitRemoteConnection(self, data):
        logger.error('recv data when connecting remote')

    def sendRemote(self, data):
        self.remote_sock.transport.write(data)

    def remoteConnectionMade(self, sock):
        self.remote_sock = sock
        self.sendConnectReply(0)
        self.state = 'sendRemote'
        logger.info('state: sendRemote')

    def sendHelloReply(self, code):
        resp = struct.pack('!BB',
                           5,
                           code)
        self.transport.write(resp)

    def sendConnectReply(self, code):
        try:
            addr = self.transport.getHost().host
        except:
            logger.error('getHost error')
            self.transport.loseConnection()
            return
        ip = [int(i) for i in addr.split('.')]
        resp = struct.pack('!BBBB',
                           5,
                           code,
                           0,
                           1)
        resp += struct.pack('!BBBB',
                            ip[0],
                            ip[1],
                            ip[2],
                            ip[3])
        resp += struct.pack('!H',
                            self.transport.getHost().port)
        self.transport.write(resp)

    def connectRemote(self, host, port):
        self.remote_factory = remote_factory(self,
                                             host=host)
        reactor.connectTCP(host,
                           port,
                           self.remote_protocol)


def run_server(config):
    port = config['port']
    ca, key, cert = config['ca'], config['key'], config['cert']
    factory = protocol.ServerFactory()
    socks5_protocol.R = client.createResolver(servers=[('8.8.8.8',
                                                        53)])
    factory.protocol = socks5_protocol
    ssl_ctx = ssl_ctx_factory(False,
                              ca,
                              key,
                              cert,
                              verify_tun)
    reactor.listenSSL(port,
                      factory,
                      ssl_ctx)
    reactor.run()


def main():
    parse_args(config)
    init_logger(config,
                logger)
    if config['daemon']:
        daemon()
    mk_pid_file(config['pidfile'])
    run_server(config)

if __name__ == '__main__':
    main()
