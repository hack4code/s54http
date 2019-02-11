#! /usr/bin/env python


import re
import struct
import logging

from twisted.names import client, dns
from twisted.internet import reactor, protocol

from utils import (
        daemonize, parse_args, ssl_ctx_factory, init_logger,
)


logger = logging.getLogger(__name__)

_dns_server = client.createResolver(servers=[('8.8.8.8', 53)])
_IP = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')


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
        logger.error('connect failed[%s]', reason.getErrorMessage())
        self.dispatcher.handleConnect(self.sock_id, 1)

    def clientConnectionLost(self, connector, reason):
        self.dispatcher.handleClose(self.sock_id)


class socks_dispatcher:

    def __init__(self, transport):
        self.socks = {}
        self.bufferes = {}
        self.connected = {}
        self.resolved = {}
        self.transport = transport

    def dispatchMessage(self, message, total_length):
        type, = struct.unpack('!B', message[4:5])
        logger.debug(
                'receive message type=%u length=%u',
                type,
                total_length
        )
        assert type in (1, 3, 5)
        if 1 == type:
            self.connectRemote(message)
        elif 3 == type:
            self.sendRemote(message, total_length)
        elif 5 == type:
            self.closeRemote(message)

    def _existedSock(self, sock_id):
        return sock_id in self.connected

    def _realConnectRemote(self, sock_id):
        addr, port = self.resolved[sock_id]
        factory = remote_factory(self, sock_id)
        reactor.connectTCP(
                addr,
                port,
                factory
        )
        self.connected[sock_id] = True

    def connectRemote(self, message):
        """
        type 1:
        +-----+------+----+------+------+
        | LEN | TYPE | ID | HOST | PORT |
        +-----+------+----+------+------+
        |  4  |   1  |  8 |      |   2  |
        +-----+------+----+------+------+
        """
        sock_id, = struct.unpack('!Q', message[5:13])

        if self._existedSock(sock_id):
            logger.error('sock_id %u connect again', sock_id)
            return

        self.connected[sock_id] = False
        self.bufferes[sock_id] = b''
        host = message[13:-2].tobytes().decode('utf-8').strip()
        port, = struct.unpack('!H', message[-2:])
        if _IP.match(host):
            self.resolved[sock_id] = (host, port)
        else:
            self.resolved[sock_id] = None

            d = _dns_server.lookupAddress(host)

            def resolve_ok(records, sock_id, host, port, dispatcher):
                if sock_id not in dispatcher.connected:
                    logger.info('sock_id %u closed at name resolving', sock_id)
                    return
                answers, *_ = records
                for answer in answers:
                    if answer.type != dns.A:
                        continue
                    addr = answer.payload.dottedQuad()
                    dispatcher.resolved[sock_id] = (addr, port)
                    if (len(dispatcher.bufferes[sock_id]) > 0 and
                            not dispatcher.connected[sock_id]):
                        dispatcher._realConnectRemote(sock_id)
                    break
                else:
                    logger.error('no ip4 address found[%s]', host)
                    dispatcher.handleConnect(sock_id, 1)

            d.addCallback(resolve_ok, sock_id, host, port, self)

            def resolve_err(res, sock_id, host, port, dispatcher):
                logger.error('resolve host failed[%s]', host)
                dispatcher.handleConnect(sock_id, 1)

            d.addErrback(resolve_err, sock_id, host, port, self)

    def handleConnect(self, sock_id, code, *, sock=None):
        """
        type 2:
        +-----+------+----+------+
        | LEN | TYPE | ID | CODE |
        +-----+------+----+------+
        |  4  |   1  |  8 |   1  |
        +-----+------+----+------+
        """
        if code == 0:
            self.socks[sock_id] = sock
            data = self.bufferes[sock_id]
            if len(data) > 0:
                sock.transport.write(data)
                self.bufferes[sock_id] = b''
        else:
            self.closeSock(sock_id)
            message = struct.pack(
                    '!IBQB',
                    14,
                    2,
                    sock_id,
                    code
            )
            self.transport.write(message)

    def sendRemote(self, message, total_length):
        """
        type 3:
        +-----+------+----+------+
        | LEN | TYPE | ID | DATA |
        +-----+------+----+------+
        |  4  |   1  |  8 |      |
        +-----+------+----+------+
        """
        sock_id, = struct.unpack('!Q', message[5:13])
        if not self._existedSock(sock_id):
            logger.error(
                'receive message type=%u for closed sock_id %u',
                3,
                sock_id
            )
            return
        data = message[13:]
        try:
            sock = self.socks[sock_id]
        except KeyError:
            self.bufferes[sock_id] += data
            if not self.connected[sock_id] and self.resolved[sock_id]:
                self._realConnectRemote(sock_id)
        else:
            sock.transport.write(data)

    def handleRemote(self, sock_id, data):
        """
        type 4:
        +-----+------+----+------+
        | LEN | TYPE | ID | DATA |
        +-----+------+----+------+
        |  4  |   1  |  8 |      |
        +-----+------+----+------+
        """
        total_length = 13 + len(data)
        header = struct.pack(
                f'!IBQ',
                total_length,
                4,
                sock_id,
        )
        self.transport.write(header)
        self.transport.write(data)

    def closeSock(self, sock_id):
        try:
            sock = self.socks[sock_id]
            del self.socks[sock_id]
            del self.resolved[sock_id]
            del self.connected[sock_id]
            del self.bufferes[sock_id]
            sock.transport.loseConnection()
        except KeyError:
            logger.error('close closed sock_id %u', sock_id)

    def closeRemote(self, message):
        """
        type 5:
        +-----+------+----+
        | LEN | TYPE | ID |
        +-----+------+----+
        |  4  |   1  |  8 |
        +-----+------+----+
        """
        sock_id, = struct.unpack('!Q', message[5:13])
        self.closeSock(sock_id)

    def handleClose(self, sock_id):
        """
        type 6:
        +-----+------+----+
        | LEN | TYPE | ID |
        +-----+------+----+
        |  4  |   1  |  8 |
        +-----+------+----+
        """
        if not self._existedSock(sock_id):
            return
        self.closeSock(sock_id)
        message = struct.pack(
                '!IBQ',
                13,
                6,
                sock_id
        )
        self.transport.write(message)


class socks5_protocol(protocol.Protocol):

    def connectionMade(self):
        self.buffer = b''
        self.dispatcher = socks_dispatcher(self.transport)

    def connectionLost(self, reason=None):
        logger.info('client closed connection')

    def dataReceived(self, data):
        self.buffer += data
        if len(self.buffer) < 4:
            return
        length, = struct.unpack('!I', self.buffer[:4])
        if len(self.buffer) < length:
            return
        message = memoryview(self.buffer)
        self.dispatcher.dispatchMessage(message, length)
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
