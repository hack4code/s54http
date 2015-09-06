from twisted.internet import reactor, protocol, ssl
import struct
import logging
import sys
from utils import daemon, write_pid_file, parse_args

config = {'port': 8000,
          'daemon': False,
          'key': 'keys/s54http.key',
          'cert': 'keys/s54http.crt',
          'pid-file': 's54http.pid',
          'log-file': 's54http.log',
          'log-level': logging.DEBUG}


class remote_protocol(protocol.Protocol):
    def connectionMade(self):
        self.socks5 = self.factory.socks5
        # send success to client
        self.socks5.send_connect_response(0)
        self.socks5.remote = self.transport
        self.socks5.state = 'communicate'

    def dataReceived(self, data):
        self.socks5.transport.write(data)


class remote_factory(protocol.ClientFactory):
    def __init__(self, socks5, host=''):
        self.protocol = remote_protocol
        self.socks5 = socks5
        self.remote_host = host

    def clientConnectionFailed(self, connector, reason):
        logging.error('connect to %s failed: %s',
                      self.remote_host, reason.getErrorMessage())
        self.socks5.send_connect_response(5)
        self.socks5.transport.loseConnection()

    def clientConnectionLost(self, connector, reason):
        logging.info('connetion to %s closed: %s',
                     self.remote_host, reason.getErrorMessage())
        self.socks5.transport.loseConnection()


class socks5_protocol(protocol.Protocol):
    def connectionMade(self):
        self.state = 'wait_hello'

    def dataReceived(self, data):
        method = getattr(self, self.state)
        method(data)

    def wait_hello(self, data):
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
                self.state = 'wait_connect'
                return
            if method == 255:
                self.transport.loseConnection()
                return
        self.transport.loseConnection()

    def wait_connect(self, data):
        (ver, cmd, rsv, atyp) = struct.unpack('!BBBB', data[:4])
        if ver != 5 or rsv != 0:
            self.transport.loseConnection()
            return
        data = data[4:]
        if cmd == 1:
            logging.info('connect')
            host = None
            if atyp == 1:  # IP V4
                (b1, b2, b3, b4) = struct.unpack('!BBBB', data[:4])
                host = '%i.%i.%i.%i' % (b1, b2, b3, b4)
                data = data[4:]
            elif atyp == 3:
                l = struct.unpack('!B', data[:1])[0]
                host = data[1:1+l].decode('utf-8')
                data = data[1+l:]
            else:
                logging.error('type %d', atyp)
                self.transport.loseConnection()
                return
            port = struct.unpack('!H', data[:2])[0]
            data = data[2:]
            logging.info('connecting %s:%d', host, port)
            return self.perform_connect(host, port)
        else:
            logging.error('cmd %d not supported', cmd)
            self.transport.loseConnection()

    def send_connect_response(self, code):
        try:
            myname = self.transport.getHost().host
        except:
            self.transport.loseConnection()
            return
        ip = [int(i) for i in myname.split('.')]
        resp = struct.pack('!BBBB', 5, code, 0, 1)
        resp += struct.pack('!BBBB', ip[0], ip[1], ip[2], ip[3])
        resp += struct.pack('!H', self.transport.getHost().port)
        self.transport.write(resp)

    def perform_connect(self, host, port):
        factory = remote_factory(self, host=host)
        reactor.connectTCP(host, port, factory)

    def communicate(self, data):
        self.remote.write(data)


def run_server():
    factory = protocol.ServerFactory()
    factory.protocol = socks5_protocol
    reactor.listenSSL(config['port'], factory,
                      ssl.DefaultOpenSSLContextFactory(config['key'],
                                                       config['cert']))
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
