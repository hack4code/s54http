#! /usr/bin/env python


import struct
import logging

from twisted.internet import reactor, protocol

from utils import (
        daemonize, parse_args, ssl_ctx_factory, init_logger,
)


logger = logging.getLogger(__name__)


config = {
        'daemon': False,
        'port': 6666,
        'ca': 'keys/ca.crt',
        'key': 'keys/server.key',
        'cert': 'keys/server.crt',
        'pidfile': 'socks.pid',
        'logfile': 'socks.log',
        'loglevel': 'INFO'
}


def verify(conn, x509, errno, errdepth, ok):
    if not ok:
        cn = x509.get_subject().commonName
        logger.error('client verify failed errno=%d cn=%s', errno, cn)
    return ok


class remote_protocol(protocol.Protocol):

    def connectionMade(self):
        self.dispatcher.handleConnect(
                self.sock_id,
                0,
                sock=self
        )

    def dataReceived(self, data):
        self.dispatcher.handleRemote(self.sock_id, data)


class remote_factory(protocol.ClientFactory):

    def __init__(self, dispatcher, sock_id):
        self.protocol = remote_protocol
        self.dispatcher = dispatcher
        self.sock_id = sock_id

    def buildProtocol(self, addr):
        p = protocol.ClientFactory.buildProtocol(self, addr)
        p.dispatcher = self.dispatcher
        p.sock_id = self.sock_id
        return p

    def clientConnectionFailed(self, connector, reason):
        logger.error(
                'connect failed %s[%s]',
                self.remote_host,
                reason.getErrorMessage()
        )
        self.dispatcher.handleConnect(self.sock_id, 1)

    def clientConnectionLost(self, connector, reason):
        logger.info(
                'connetion to %s closed: %s',
                self.remote_host,
                reason.getErrorMessage()
        )
        self.dispatcher.handleClose(self.sock_id)


class socks_dispatcher:

    def __init__(self, transport):
        self.socks = {}
        self.transport = transport

    def dispatchMessage(self, message):
        type = struct.unpack('!B', message[2:3])
        if 1 == type:
            self.connectRemote(message)
        elif 3 == type:
            self.sendRemote(message)
        elif 5 == type:
            self.closeRemote(message)
        else:
            logger.error('unknown message type %d', type)

    def connectRemote(self, message):
        """
        type 1:
        +-----+------+----+------+------+
        | LEN | TYPE | ID | ADDR | PORT |
        +-----+------+----+------+------+
        |  2  |   1  | 4  |   4  |   2  |
        +-----+------+----+------+------+
        """
        sock_id = struct.unpack('!i', message[3:7])
        ip = struct.unpack('!BBBB', message[7:11])
        host = '.'.join(str(item) for item in ip)
        port = struct.unpack('!H', message[11:13])
        factory = remote_factory(self, sock_id)
        reactor.connectTCP(host, port, factory)

    def handleConnect(self, sock_id, code, *, sock=None):
        """
        type 2:
        +-----+------+----+------+
        | LEN | TYPE | ID | CODE |
        +-----+------+----+------+
        |  2  |   1  | 4  |   1  |
        +-----+------+----+------+
        """
        if code == 0:
            assert sock
            self.socks[sock_id] = sock
        message = struct.pack(
                '!HBiB',
                8,
                2,
                sock_id,
                code
        )
        self.transport.write(message)

    def sendRemote(self, message):
        """
        type 3:
        +-----+------+----+------+
        | LEN | TYPE | ID | DATA |
        +-----+------+----+------+
        |  2  |   1  | 4  |      |
        +-----+------+----+------+
        """
        sock_id = struct.unpack('!i', message[3:7])
        data = struct.unpack('!s', message[7:])
        try:
            sock = self.socks[sock_id]
        except KeyError:
            logger.error('send to unknown sock %d', sock_id)
        else:
            sock.transport.write(data)

    def handleRemote(self, sock_id, data):
        """
        type 4:
        +-----+------+----+------+
        | LEN | TYPE | ID | DATA |
        +-----+------+----+------+
        |  2  |   1  |  4 |      |
        +-----+------+----+------+
        """
        length = 7 + len(data)
        message = struct.pack(
                '!HBis',
                length,
                4,
                sock_id,
                data
        )
        self.transport.write(message)

    def closeRemote(self, message):
        """
        type 5:
        +-----+------+----+
        | LEN | TYPE | ID |
        +-----+------+----+
        |  2  |   1  |  4 |
        +-----+------+----+
        """
        sock_id = struct.unpack('!i', message[3:7])
        try:
            sock = self.socks[sock_id]
        except KeyError:
            logger.error('close unknown receive sock %d', sock_id)
        else:
            sock.transport.loseConnection()
            del self.socks[sock_id]

    def handleClose(self, sock_id):
        """
        type 6:
        +-----+------+----+
        | LEN | TYPE | ID |
        +-----+------+----+
        |  2  |   1  |  4 |
        +-----+------+----+
        """
        message = struct.pack(
                '!HBi',
                7,
                6,
                sock_id
        )
        self.transport.write(message)
        try:
            del self.socks[sock_id]
        except KeyError:
            logger.error('close unknown send sock %d', sock_id)


class socks5_protocol(protocol.Protocol):

    def connectionMade(self):
        self.buf = b''
        self.dispatcher = socks_dispatcher(self.transport)

    def connectionLost(self, reason=None):
        logger.info('connetion closed')

    def dataReceived(self, data):
        self.buffer += data
        if len(self.buffer) < 2:
            return
        length = struct.unpack('!h', self.buffer[:2])
        if len(self.buffer) < length:
            return
        self.dispatcher.dispatchMessage(self.buffer)
        self.buffer = self.buffer[length:]


def start_server(config):
    port = config['port']
    ca, key, cert = config['ca'], config['key'], config['cert']
    factory = protocol.ServerFactory()
    factory.protocol = socks5_protocol
    ssl_ctx = ssl_ctx_factory(
            False,
            ca,
            key,
            cert,
            verify
    )
    reactor.listenSSL(port, factory, ssl_ctx)
    reactor.run()


def main():
    parse_args(config)
    init_logger(config, logger)
    if config['daemon']:
        pidfile = config['pidfile']
        logfile = config['logfile']
        daemonize(
                pidfile,
                stdout=logfile,
                stderr=logfile
        )
    start_server(config)


if __name__ == '__main__':
    main()
