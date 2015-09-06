from twisted.internet import reactor, protocol, ssl
import logging
import sys
from utils import daemon, parse_args, write_pid_file

config = {'server': '127.0.0.1',
          'sport': 8000,
          'port': 8080,
          'daemon': False,
          'pid-file': 's5tun.pid',
          'log-file': 's5tun.log',
          'log-level': logging.DEBUG}


class sock_remote(protocol.Protocol):
    def connectionMade(self):
        self.local_sock = self.factory.local_sock
        self.local_sock.remote = self.transport
        self.local_sock.remoteConnectionMade()

    def dataReceived(self, data):
        self.local_sock.transport.write(data)


class remote_factory(protocol.ClientFactory):
    def __init__(self, sock):
        self.protocol = sock_remote
        self.local_sock = sock

    def clientConnectionFailed(self, connector, reason):
        logging.error('connect to socks5 proxy server failed: %s',
                      reason.getErrorMessage())
        self.local_sock.transport.loseConnection()

    def clientConnectionLost(self, connector, reason):
        logging.info('connetion to socks5 proxy server closed: %s',
                     reason.getErrorMessage())
        self.local_sock.transport.loseConnection()


class sock_local(protocol.Protocol):
    def __init__(self):
        self.state = 'wait_remote'
        self.buf = []

    def connectionMade(self):
        factory = remote_factory(self)
        reactor.connectSSL(config['server'], config['sport'], factory,
                           ssl.ClientContextFactory())
        pass

    def dataReceived(self, data):
        method = getattr(self, self.state)
        method(data)

    def wait_remote(self, data):
        self.buf.append(data)

    def send_remote(self, data):
        self.remote.write(data)

    def remoteConnectionMade(self):
        self.state = 'send_remote'
        for data in self.buf:
            self.send_remote(data)


def run_server():
    factory = protocol.ServerFactory()
    factory.protocol = sock_local
    reactor.listenTCP(config['port'], factory)
    reactor.run()


def main():
    parse_args(sys.argv[1:], config)
    logging.basicConfig(filename=config['log-file'],
                        level=config['log-level'],
                        format='%(asctime)s %(levelname)-8s %(message)s')
    if config['daemon']:
        daemon()
    write_pid_file(config['pid-file'])
    run_server()

if __name__ == '__main__':
    main()
