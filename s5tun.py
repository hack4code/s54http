#! /bin/env python


from twisted.internet import reactor, protocol
import logging
import sys

from utils import daemon, parse_args, write_pid_file, ssl_ctx_factory

config = {'server': '103.55.27.122',
          'sport': 6666,
          'port': 8080,
          'ca': 'keys/ca.crt',
          'key': 'keys/s5tun.key',
          'cert': 'keys/s5tun.crt',
          'pid-file': 's5tun.pid',
          'log-file': 's5tun.log',
          'daemon': False,
          'log-level': logging.DEBUG}


def verify_proxy(conn, x509, errno, errdepth, ok):
    if not ok:
        cn = x509.get_subject().commonName
        logging.error('socks5 proxy server verify failed: errno=%d cn=%s',
                      errno, cn)
    return ok


class sock_remote_protocol(protocol.Protocol):
    def connectionMade(self):
        self.local_sock.remoteConnectionMade(self)

    def dataReceived(self, data):
        self.local_sock.transport.write(data)


class sock_remote_factory(protocol.ClientFactory):
    def __init__(self, sock):
        self.protocol = sock_remote_protocol
        self.local_sock = sock

    def buildProtocol(self, addr):
        p = protocol.ClientFactory.buildProtocol(self, addr)
        p.local_sock = self.local_sock
        return p

    def clientConnectionFailed(self, connector, reason):
        logging.error('connect to socks5 proxy server failed: %s',
                      reason.getErrorMessage())
        self.local_sock.transport.loseConnection()

    def clientConnectionLost(self, connector, reason):
        logging.info('connetion to socks5 proxy server closed: %s',
                     reason.getErrorMessage())
        self.local_sock.transport.loseConnection()


class sock_local_factory(protocol.ServerFactory):
    def __init__(self, saddr, sport, ca, key, cert):
        self.saddr, self.sport = saddr, sport
        self.ctx_factory = ssl_ctx_factory(True, ca, key, cert, verify_proxy)
        self.protocol = sock_local_protocol

    def buildProtocol(self, addr):
        p = protocol.ServerFactory.buildProtocol(self, addr)
        p.saddr, p.sport = self.saddr, self.sport
        p.ctx_factory = self.ctx_factory
        p.connectRemote()
        return p


class sock_local_protocol(protocol.Protocol):
    def __init__(self):
        self.state = 'waitRemote'
        self.buf = b''

    def dataReceived(self, data):
        method = getattr(self, self.state)
        method(data)

    def connectRemote(self):
        remote_factory = sock_remote_factory(self)
        reactor.connectSSL(self.saddr, self.sport,
                           remote_factory, self.ctx_factory)

    def waitRemote(self, data):
        # save data when proxy server not connected
        self.buf += data

    def sendRemote(self, data):
        assert self.remote_sock is not None
        self.remote_sock.transport.write(data)

    def remoteConnectionMade(self, sock):
        self.remote_sock = sock
        self.state = 'sendRemote'
        self.sendRemote(self.buf)


def run_server(port, saddr, sport, ca, key, cert):
    local_factory = sock_local_factory(saddr, sport, ca, key, cert)
    reactor.listenTCP(port, local_factory)
    reactor.run()


def main():
    parse_args(sys.argv[1:], config)
    log_file, log_level = config['log-file'], config['log-level']
    port = config['port']
    saddr, sport = config['server'], config['sport']
    ca, key, cert = config['ca'], config['key'], config['cert']
    pid_file = config['pid-file']
    logging.basicConfig(filename=log_file, level=log_level,
                        format='%(asctime)s %(levelname)-8s %(message)s')
    if config['daemon']:
        daemon()
    write_pid_file(pid_file)
    run_server(port, saddr, sport, ca, key, cert)

if __name__ == '__main__':
    main()
