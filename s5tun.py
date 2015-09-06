from twisted.internet import reactor, protocol
import logging
import sys
from OpenSSL import ssl
from utils import daemon, parse_args, write_pid_file

config = {'server': '127.0.0.1',
          'sport': 8000,
          'port': 8080,
          'daemon': False,
          'ca': 'keys/ca.crt',
          'pid-file': 's5tun.pid',
          'log-file': 's5tun.log',
          'log-level': logging.DEBUG}


def verify(conn, x509, errno, errdepth, retcode):
    cn = x509.get_subject().commonName
    if cn != 's54http':
        return False
    else:
        return True


class ssl_context_factory:
    isClient = 1

    def getContext(self):
        ctx = ssl.Context(ssl.PROTOCOL_TLSv1)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.set_verify(ssl.VERIFY_PEER | ssl.VERIFY_FAIL_IF_NO_PEER_CERT,
                       verify)
        ca = config['ca']
        ctx.load_verify_locations(cafile=ca)
        return ctx


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
        factory = sock_remote_factory(self)
        ctx_factory = ssl_context_factory()
        addr, port = config['server'], config['sport']
        reactor.connectSSL(addr, port, factory, ctx_factory)

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
