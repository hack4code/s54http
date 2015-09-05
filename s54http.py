from twisted.internet import reactor, protocol
import struct
import logging
import getopt
import sys
import os
import time

config = {'port': 8080,
          'daemon': False}


class remote_protocol(protocol.Protocol):
    def connectionMade(self):
        self.socks5 = self.factory.socks5
        # -- send success to client
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
            logging.error("version %d not supported", ver)
            self.transport.loseConnection()
            return
        if nmethods < 1:
            logging.error("nmethods = %d", nmethods)
            self.transport.loseConnection()
            return
        methods = data[2:2+nmethods]
        for meth in methods:
            logging.info('method = %x', meth)
            if meth == 0:
                # no auth, neato, accept
                resp = struct.pack('!BB', 5, 0)
                self.transport.write(resp)
                self.state = 'wait_connect'
                return
            if meth == 255:
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
            logging.info('CONNECT')
            host = None
            if atyp == 1:  # IP V4
                logging.info('ipv4')
                (b1, b2, b3, b4) = struct.unpack('!BBBB', data[:4])
                host = '%i.%i.%i.%i' % (b1, b2, b3, b4)
                data = data[4:]
            elif atyp == 3:
                logging.info('name')
                l = struct.unpack('!B', data[:1])[0]
                host = data[1:1+l].decode('utf-8')
                data = data[1+l:]
            elif atyp == 4:  # IP V6
                logging.error('ipv6 not supported')
            else:
                self.transport.loseConnection()
                return
            port = struct.unpack('!H', data[:2])
            data = data[2:]
            logging.info('connecting %s:%d', host, port)
            return self.perform_connect(host, port)
        elif cmd == 2:
            logging.info('BIND')
        elif cmd == 3:
            logging.info('UDP ASSOCIATE')
        # we should have processed the request by now
        self.transport.loseConnection()

    def send_connect_response(self, code):
        try:
            myname = self.transport.getHost().host
        except:
            # this might fail as no longer a socket
            # is present
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


def daemon():
    pid = os.fork()
    if pid > 0:
        time.sleep(5)
        sys.exit(0)
    sys.stdin.close()


def main():
    shortopts = 'dp:'
    longopts = 'pid-file='
    optlist, args = getopt.getopt(sys.argv[1:], shortopts, longopts)
    for k, v in optlist:
        if k == '-p':
            config['port'] = int(v)
        if k == '-d':
            config['daemon'] = True
    if config['daemon']:
        daemon()
    logging.basicConfig(level=logging.DEBUG)
    factory = protocol.ServerFactory()
    factory.protocol = socks5_protocol
    reactor.listenTCP(config['port'], factory)
    reactor.run()

if __name__ == '__main__':
    main()
