#! /bin/env python


from twisted.internet import reactor, protocol
import logging
import sys

from utils import daemon, parse_args, write_pid_file, ssl_ctx_factory

config = {'server': '127.0.0.1',
          'sport': 8000,
          'port': 8080,
          'ca': 'keys/ca.crt',
          'key': 'keys/s5tun.key',
          'cert': 'keys/s5tun.crt',
          'pid-file': 's5tun.pid',
          'log-file': 's5tun.log',
          'daemon': False,
          'log-level': logging.DEBUG}


def verify_proxy(conn, x509, errno, errdepth, ok):
    if ok:
        cn = x509.get_subject().commonName
        if cn == 's54http':
            return True
    logging.error('socks5 proxy server verify failed: errno=%d', errno)
    return False


class sock_remote_protocol(protocol.Protocol):
    def connectionMade(self):
        self.local_sock = self.factory.local_sock
        self.local_sock.remote = self.transport
        self.local_sock.remoteConnectionMade()

    def dataReceived(self, data):
        self.local_sock.transport.write(data)


class sock_remote_factory(protocol.ClientFactory):
    def __init__(self, sock):
        self.protocol = sock_remote_protocol
        self.local_sock = sock

    def clientConnectionFailed(self, connector, reason):
        logging.error('connect to socks5 proxy server failed: %s',
                      reason.getErrorMessage())
        self.local_sock.transport.loseConnection()

    def clientConnectionLost(self, connector, reason):
        logging.info('connetion to socks5 proxy server closed: %s',
                     reason.getErrorMessage())
        self.local_sock.transport.loseConnection()


class sock_local_protocol(protocol.Protocol):
    def __init__(self):
        self.state = 'wait_remote'
        self.buf = []
        self.connect_remote()

    def connectionMade(self):
        pass

    def dataReceived(self, data):
        method = getattr(self, self.state)
        method(data)

    def connect_remote(self):
        ca, key, cert = config['ca'], config['key'], config['cert']
        addr, port = config['server'], config['sport']
        factory = sock_remote_factory(self)
        ctx_factory = ssl_ctx_factory(ca, key, cert, verify_proxy)
        reactor.connectSSL(addr, port, factory, ctx_factory)

    def wait_remote(self, data):
        self.buf.append(data)

    def send_remote(self, data):
        self.remote.write(data)

    def remoteConnectionMade(self):
        self.state = 'send_remote'
        for data in self.buf:
            self.send_remote(data)
        self.buf = []


def run_server():
    factory = protocol.ServerFactory()
    factory.protocol = sock_local_protocol
    port = config['port']
    reactor.listenTCP(port, factory)
    reactor.run()


def main():
    parse_args(sys.argv[1:], config)
    log_file, log_level = config['log-file'], config['log-level']
    logging.basicConfig(filename=log_file, level=log_level,
                        format='%(asctime)s %(levelname)-8s %(message)s')
    if config['daemon']:
        daemon()
    pid_file = config['pid-file']
    write_pid_file(pid_file)
    run_server()

if __name__ == '__main__':
    main()
