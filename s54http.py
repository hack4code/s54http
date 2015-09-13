#! /bin/env python


from twisted.internet import reactor, protocol
import struct
import logging
import sys

from utils import daemon, write_pid_file, parse_args, ssl_ctx_factory

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
        self.local_sock.remoteConnectionmade(self)

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
        self.local_sock.sendConresp(5)
        self.local_sock.transport.loseConnection()

    def clientConnectionLost(self, connector, reason):
        logging.info('connetion to %s closed: %s',
                     self.remote_host, reason.getErrorMessage())
        self.local_sock.transport.loseConnection()


class socks5_protocol(protocol.Protocol):

    def connectionMade(self):
        self.state = 'waitHello'

    def dataReceived(self, data):
        method = getattr(self, self.state)
        method(data)

    def waitHello(self, data):
        (ver, nmethods) = struct.unpack('!BB', data[:2])
        logging.info('version = %d, nmethods = %d' %
                     (ver, nmethods))
        if ver != 5:
            logging.error('socks %d not supported', ver)
            self.transport.loseConnection()
            return
        if nmethods < 1:
            logging.error('no method')
            self.transport.loseConnection()
            return
        methods = data[2:2+nmethods]
        for method in methods:
            logging.info('method = %x', method)
            if method == 0:
                resp = struct.pack('!BB', 5, 0)
                self.transport.write(resp)
                self.state = 'waitConnectRemote'
                logging.info('state: waitConnectRemote')
                return
        self.transport.loseConnection()

    def waitConnectRemote(self, data):
        (ver, cmd, rsv, atyp) = struct.unpack('!BBBB', data[:4])
        if ver != 5 or rsv != 0:
            logging.error('ver: %d rsv: %d', ver, rsv)
            self.transport.loseConnection()
            return
        data = data[4:]
        if cmd == 1:
            if atyp == 1:  # addr
                (b1, b2, b3, b4) = struct.unpack('!BBBB', data[:4])
                host = '%i.%i.%i.%i' % (b1, b2, b3, b4)
                data = data[4:]
                port = struct.unpack('!H', data[:2])[0]
                data = data[2:]
                self.state = 'waitRemoteconn'
                logging.info('state: waitRemoteconn')
                self.connectRemote(host, port)
                logging.info('connect %s:%d', host, port)
                return
            elif atyp == 3:  # name
                l = struct.unpack('!B', data[:1])[0]
                host = data[1:1+l].decode('utf-8')
                data = data[1+l:]
                port = struct.unpack('!H', data[:2])[0]
                data = data[2:]
                d = reactor.resolve(host)

                def resolve_ok(addr, port):
                    self.state = 'waitRemoteconn'
                    logging.info('state: waitRemoteconn')
                    self.connectRemote(addr, port)
                    logging.info('connecting %s:%d', addr, port)

                d.addCallback(resolve_ok, port)

                def resolve_err(res):
                    logging.error('name resolve err: %s', res)
                    self.sendConresp(5)
                    self.transport.loseConnection()

                d.addErrback(resolve_err)
                self.state = 'waitNameRes'
                logging.info('state: waitNameres')
                return
            else:
                logging.error('type %d', atyp)
                self.transport.loseConnection()
                return
        else:
            logging.error('command %d not supported', cmd)
            self.transport.loseConnection()

    def waitNameres(self, data):
        logging.error('recv data when name resolving')

    def waitRemoteconn(self, data):
        logging.error('recv data when connecting remote')

    def sendRemote(self, data):
        self.remote_sock.transport.write(data)

    def remoteConnectionmade(self, sock):
        self.remote_sock = sock
        self.sendConresp(0)
        self.state = 'sendRemote'
        logging.info('state: sendRemote')

    def sendConresp(self, code):
        try:
            addr = self.transport.getHost().host
        except:
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
