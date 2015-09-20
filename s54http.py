#! /bin/env python


from twisted.internet import reactor, protocol
import struct
import logging
import sys

from utils import daemon, write_pid_file, parse_args, \
    ssl_ctx_factory, dns_cache

config = {'port': 6666,
          'ca': 'keys/ca.crt',
          'capath': 'keys/',
          'key': 'keys/s54http.key',
          'cert': 'keys/s54http.crt',
          'pid-file': 's54http.pid',
          'log-file': 's54http.log',
          'daemon': False,
          'log-level': logging.DEBUG}


def verify_tun(conn, x509, errno, errdepth, ok):
    if not ok:
        cn = x509.get_subject().commonName
        logging.error('client verify failed: errno=%d cn=%s', errno, cn)
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
        p = protocol.ClientFactory.buildProtocol(self, addr)
        p.local_sock = self.local_sock
        return p

    def clientConnectionFailed(self, connector, reason):
        logging.error('connect %s failed: %s',
                      self.remote_host, reason.getErrorMessage())
        self.local_sock.sendConnectReply(5)
        self.local_sock.transport.loseConnection()

    def clientConnectionLost(self, connector, reason):
        logging.info('connetion to %s closed: %s',
                     self.remote_host, reason.getErrorMessage())
        self.local_sock.transport.loseConnection()


ncache = dns_cache(10000)


class socks5_protocol(protocol.Protocol):

    def connectionMade(self):
        self.state = 'waitHello'
        self.buf = b''

    def dataReceived(self, data):
        method = getattr(self, self.state)
        method(data)

    def waitHello(self, data):
        self.buf += data
        if len(self.buf) < 2:
            return
        (ver, nmethods) = struct.unpack('!BB', self.buf[:2])
        logging.info('version = %d, nmethods = %d' %
                     (ver, nmethods))
        if ver != 5:
            logging.error('socks %d not supported', ver)
            self.sendHelloReply(0xFF)
            self.transport.loseConnection()
            return
        if nmethods < 1:
            logging.error('no method')
            self.sendHelloReply(0xFF)
            self.transport.loseConnection()
            return
        if len(self.buf) < (nmethods + 2):
            return
        for method in self.buf[2:2+nmethods]:
            if method == 0:  # no authentication
                self.buf = b''
                self.state = 'waitConnectRemote'
                logging.info('state: waitConnectRemote')
                self.sendHelloReply(0)
                return
        self.sendHelloReply(0xFF)
        self.transport.loseConnection()

    def waitConnectRemote(self, data):
        self.buf += data
        if (len(self.buf) < 4):
            return
        (ver, cmd, rsv, atyp) = struct.unpack('!BBBB', data[:4])
        if ver != 5 or rsv != 0:
            logging.error('ver: %d rsv: %d', ver, rsv)
            self.transport.loseConnection()
            return
        if cmd == 1:
            if atyp == 1:  # addr
                if (len(self.buf) < 10):
                    return
                (b1, b2, b3, b4) = struct.unpack('!BBBB', self.buf[4:8])
                host = '%i.%i.%i.%i' % (b1, b2, b3, b4)
                (port) = struct.unpack('!H', self.buf[8:10])
                self.buf = b''
                self.state = 'waitRemoteConnection'
                logging.info('state: waitRemoteConnection')
                self.connectRemote(host, port)
                logging.info('connect %s:%d', host, port)
                return
            elif atyp == 3:  # name
                if (len(self.buf) < 5):
                    return
                (nlen, ) = struct.unpack('!B', self.buf[4:5])
                if (len(self.buf) < (5 + nlen + 2)):
                    return
                host = self.buf[5:5+nlen].decode('utf-8')
                (port, ) = struct.unpack('!H', self.buf[5+nlen:7+nlen])
                self.buf = b''

                if host in ncache:
                    self.connectRemote(ncache[host], port)
                    logging.info('connect %s:%d', host, port)
                    self.state = 'waitRemoteConnection'
                    logging.info('state: waitRemoteConnection')
                    return

                d = reactor.resolve(host)

                def resolve_ok(addr, host, port):
                    ncache[host] = addr
                    self.connectRemote(addr, port)
                    logging.info('connecting %s:%d', addr, port)
                    self.state = 'waitRemoteConnection'
                    logging.info('state: waitRemoteConnection')

                d.addCallback(resolve_ok, host, port)

                def resolve_err(res):
                    logging.error('name resolve err: %s', res)
                    self.sendConnectReply(5)
                    self.transport.loseConnection()

                d.addErrback(resolve_err)
                self.state = 'waitNameRes'
                logging.info('state: waitNameResolve')
                return
            else:
                logging.error('type %d', atyp)
                self.transport.loseConnection()
                return
        else:
            logging.error('command %d not supported', cmd)
            self.transport.loseConnection()

    def waitNameResolve(self, data):
        logging.error('recv data when name resolving')

    def waitRemoteConnection(self, data):
        logging.error('recv data when connecting remote')

    def sendRemote(self, data):
        assert self.remote_sock is not None
        self.remote_sock.transport.write(data)

    def remoteConnectionMade(self, sock):
        self.remote_sock = sock
        self.sendConnectReply(0)
        self.state = 'sendRemote'
        logging.info('state: sendRemote')

    def sendHelloReply(self, code):
        resp = struct.pack('!BB', 5, code)
        self.transport.write(resp)

    def sendConnectReply(self, code):
        try:
            addr = self.transport.getHost().host
        except:
            logging.error('getHost error')
            self.transport.loseConnection()
            return
        ip = [int(i) for i in addr.split('.')]
        resp = struct.pack('!BBBB', 5, code, 0, 1)
        resp += struct.pack('!BBBB', ip[0], ip[1], ip[2], ip[3])
        resp += struct.pack('!H', self.transport.getHost().port)
        self.transport.write(resp)

    def connectRemote(self, host, port):
        factory = remote_factory(self, host=host)
        reactor.connectTCP(host, port, factory)


def run_server(port, ca, capath, key, cert):
    factory = protocol.ServerFactory()
    factory.protocol = socks5_protocol
    ctx_factory = ssl_ctx_factory(False, ca, capath, key, cert, verify_tun)
    reactor.listenSSL(port, factory, ctx_factory)
    reactor.run()


def main():
    parse_args(sys.argv[1:], config)
    log_file, log_level = config['log-file'], config['log-level']
    pid_file = config['pid-file']
    port = config['port']
    ca, capath = config['ca'], config['capath']
    key, cert = config['key'], config['cert']
    logging.basicConfig(filename=log_file, level=log_level,
                        format='%(asctime)s %(levelname)-8s %(message)s')
    if config['daemon']:
        daemon()
    write_pid_file(pid_file)
    run_server(port, ca, capath, key, cert)

if __name__ == '__main__':
    main()
