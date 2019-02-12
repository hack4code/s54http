#! /usr/bin/env python
# -*- coding: utf-8 -*-


import struct
import logging

from twisted.internet import reactor, protocol

from utils import (
        SSLCtxFactory,
        daemonize, parse_args, init_logger
)


config = {
        'daemon': False,
        'saddr': '',
        'sport': 8080,
        'port': 8080,
        'ca': 'keys/ca.crt',
        'key': 'keys/client.key',
        'cert': 'keys/client.crt',
        'pidfile': 'socks.pid',
        'logfile': 'socks.log',
        'loglevel': 'INFO'
}
logger = logging.getLogger(__name__)

_SOCK_ID = 0


def verify(conn, x509, errno, errdepth, ok):
    if not ok:
        cn = x509.get_subject().commonName
        logger.error(
                'server verify failed errno=%d cn=%s',
                errno,
                cn
        )
    return ok


def next_sock_id():
    global _SOCK_ID

    _SOCK_ID = _SOCK_ID + 1
    return _SOCK_ID


class TunnelProtocol(protocol.Protocol):

    def __init__(self):
        self.buffer = b''

    def connectionMade(self):
        self.dispatcher.transport = self.transport

    def dataReceived(self, data):
        self.buffer += data
        if len(self.buffer) < 4:
            return
        length, = struct.unpack('!I', self.buffer[:4])
        if len(self.buffer) < length:
            return
        message = memoryview(self.buffer)[:length]
        self.dispatcher.dispatchMessage(message)
        self.buffer = self.buffer[length:]


class TunnelFactory(protocol.ClientFactory):

    def __init__(self, dispatcher):
        self.protocol = TunnelProtocol
        self.dispatcher = dispatcher

    def buildProtocol(self, addr):
        p = protocol.ClientFactory.buildProtocol(self, addr)
        p.dispatcher = self.dispatcher
        return p

    def clientConnectionFailed(self, connector, reason):
        message = reason.getErrorMessage()
        raise RuntimeError(f'connect server failed[{message}]')

    def clientConnectionLost(self, connector, reason):
        logger.info(
                'connetion to server closed[%s]',
                reason.getErrorMessage()
        )


class SocksDispatcher:

    def __init__(self, addr, port, ssl_ctx):
        factory = TunnelFactory(self)
        reactor.connectSSL(
                addr,
                port,
                factory,
                ssl_ctx
        )
        self.socks = {}

    def dispatchMessage(self, message):
        type, = struct.unpack('!B', message[4:5])
        if 2 == type:
            self.handleConnect(message)
        elif 4 == type:
            self.handleRemote(message)
        elif 6 == type:
            self.handleClose(message)
        else:
            logger.error('receive unknown message type=%u', type)

    def closeSock(self, sock_id):
        try:
            sock = self.socks[sock_id]
        except KeyError:
            logger.error('close closed sock_id[%u]', sock_id)
        else:
            sock.transport.loseConnection()
            del self.socks[sock_id]

    def connectRemote(self, sock, host, port):
        """
        type 1:
        +-----+------+----+------+------+
        | LEN | TYPE | ID | HOST | PORT |
        +-----+------+----+------+------+
        |  4  |   1  |  8 |      |   2  |
        +-----+------+----+------+------+
        """
        sock_id = sock.sock_id
        self.socks[sock_id] = sock
        host_length = len(host)
        total_length = 15 + host_length
        logger.info(
                'sock_id[%u] connect %s:%u',
                sock_id,
                host.decode('utf-8'),
                port,
        )
        message = struct.pack(
                f'!IBQ{host_length}sH',
                total_length,
                1,
                sock_id,
                host,
                port
        )
        self.transport.write(message)

    def handleConnect(self, message):
        """
        type 2:
        +-----+------+----+------+
        | LEN | TYPE | ID | CODE |
        +-----+------+----+------+
        |  4  |   1  |  8 |   1  |
        +-----+------+----+------+
        """
        sock_id, code = struct.unpack('!QB', message[5:14])
        if 0 == code:
            return
        logger.info('sock_id[%u] connect failed', sock_id)
        self.closeSock(sock_id)

    def sendRemote(self, sock, data):
        """
        type 3:
        +-----+------+----+------+
        | LEN | TYPE | ID | DATA |
        +-----+------+----+------+
        |  4  |   1  |  8 |      |
        +-----+------+----+------+
        """
        sock_id = sock.sock_id
        logger.debug(
                'sock_id[%u] send data length=%u to %s:%u',
                sock_id,
                len(data),
                sock.remote_host,
                sock.remote_port
        )
        total_length = 13 + len(data)
        header = struct.pack(
                f'!IBQ',
                total_length,
                3,
                sock_id,
        )
        self.transport.write(header)
        self.transport.write(data)

    def handleRemote(self, message):
        """
        type 4:
        +-----+------+----+------+
        | LEN | TYPE | ID | DATA |
        +-----+------+----+------+
        |  4  |   1  |  8 |      |
        +-----+------+----+------+
        """
        sock_id, = struct.unpack(f'!Q', message[5:13])
        data = message[13:]
        try:
            sock = self.socks[sock_id]
        except KeyError:
            logger.error('receive data for closed sock_id[%u]', sock_id)
        else:
            logger.debug(
                    'sock_id[%u] receive data length=%u from %s:%u',
                    sock_id,
                    len(data),
                    sock.remote_host,
                    sock.remote_port
            )
            sock.transport.write(data)

    def closeRemote(self, sock):
        """
        type 5:
        +-----+------+----+
        | LEN | TYPE | ID |
        +-----+------+----+
        |  4  |   1  |  8 |
        +-----+------+----+
        """
        sock_id = sock.sock_id
        if sock_id not in self.socks:
            return
        logger.info('sock_id[%u] local closed', sock_id)
        self.closeSock(sock_id)
        message = struct.pack(
                '!IBQ',
                13,
                5,
                sock_id
        )
        self.transport.write(message)

    def handleClose(self, message):
        """
        type 6:
        +-----+------+----+
        | LEN | TYPE | ID |
        +-----+------+----+
        |  4  |   1  |  8 |
        +-----+------+----+
        """
        sock_id, = struct.unpack('!Q', message[5:13])
        logger.info('sock_id[%u] remote closed', sock_id)
        self.closeSock(sock_id)


class Socks5Protocol(protocol.Protocol):

    def __init__(self):
        self.remote_host = None
        self.remote_port = None
        self.buffer = None
        self.state = None
        self.dispatcher = None
        self.sock_id = next_sock_id()

    def connectionMade(self):
        self.state = 'waitHello'
        self.buffer = b''

    def connectionLost(self, reason=None):
        self.dispatcher.closeRemote(self)

    def dataReceived(self, data):
        method = getattr(self, self.state)
        method(data)

    def waitHello(self, data):
        self.buffer += data
        if len(self.buffer) < 2:
            return
        version, nmethods = struct.unpack('!BB', self.buffer[:2])
        if version != 5:
            logger.error('unsupported version %u', version)
            self.sendHelloReply(0xFF)
            self.transport.loseConnection()
            return
        if nmethods < 1:
            logger.error('no methods found')
            self.sendHelloReply(0xFF)
            self.transport.loseConnection()
            return
        if len(self.buffer) < nmethods + 2:
            return
        for method in self.buffer[2:2+nmethods]:
            if method == 0:
                self.buffer = b''
                self.state = 'waitConnectRemote'
                self.sendHelloReply(0)
                return
        self.sendHelloReply(0xFF)
        self.transport.loseConnection()

    def sendHelloReply(self, rep):
        response = struct.pack('!BB', 5, rep)
        self.transport.write(response)

    def waitConnectRemote(self, data):
        self.buffer += data
        if len(self.buffer) < 4:
            return
        version, command, reserved, atyp = struct.unpack(
                '!BBBB',
                self.buffer[:4]
        )
        if version != 5:
            logger.error('unsupported version %u', version)
            self.transport.loseConnection()
            return
        if reserved != 0:
            logger.error('reserved value not 0')
            self.transport.loseConnection()
            return
        if command != 1:
            logger.error('unsupported command %u', command)
            self.sendConnectReply(7)
            self.transport.loseConnection()
            return
        if atyp not in (1, 3):
            logger.error('unsupported atyp %u', atyp)
            self.sendConnectReply(8)
            self.transport.loseConnection()
            return
        if atyp == 1:
            if len(self.buffer) < 10:
                return
            ip1, ip2, ip3, ip4 = struct.unpack('!BBBB', self.buffer[4:8])
            host = f'{ip1}.{ip2}.{ip3}.{ip4}'.encode('utf-8')
            port, = struct.unpack('!H', self.buffer[8:10])
        elif atyp == 3:
            if len(self.buffer) < 5:
                return
            length, = struct.unpack('!B', self.buffer[4:5])
            if len(self.buffer) < 5 + length + 2:
                return
            host = self.buffer[5:5+length]
            port, = struct.unpack('!H', self.buffer[5+length:7+length])
        self.connectRemote(host, port)

    def sendConnectReply(self, rep):
        response = struct.pack(
                '!BBBBBBBBH',
                5,
                rep,
                0,
                1,
                0,
                0,
                0,
                0,
                0
        )
        self.transport.write(response)

    def connectRemote(self, host, port):
        self.remote_host = host.decode('utf-8').strip()
        self.remote_port = port
        self.dispatcher.connectRemote(self, host, port)
        self.sendConnectReply(0)
        self.buffer = b''
        self.state = 'sendRemote'

    def sendRemote(self, data):
        self.dispatcher.sendRemote(self, data)


class Socks5Factory(protocol.ServerFactory):

    def __init__(self, dispatcher):
        self.protocol = Socks5Protocol
        self.dispatcher = dispatcher

    def buildProtocol(self, addr):
        p = protocol.ServerFactory.buildProtocol(self, addr)
        p.dispatcher = self.dispatcher
        return p


def start_server(config):
    port = config['port']
    remote_addr, remote_port = config['saddr'], config['sport']
    ca, key, cert = config['ca'], config['key'], config['cert']
    ssl_ctx = SSLCtxFactory(
            True,
            ca,
            key,
            cert,
            verify
    )
    dispatcher = SocksDispatcher(remote_addr, remote_port, ssl_ctx)
    factory = Socks5Factory(dispatcher)
    reactor.listenTCP(
            port,
            factory,
            interface='127.0.0.1'
    )
    reactor.run()


def main():
    parse_args(config)
    if not config['saddr']:
        raise RuntimeError('no server address found')
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
