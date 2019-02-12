#! /usr/bin/env python
# -*- coding: utf-8 -*-


import re
import struct
import logging

from twisted.names import client, dns
from twisted.internet import reactor, protocol

from utils import (
        SSLCtxFactory, Cache,
        daemonize, parse_args, init_logger,
)


logger = logging.getLogger(__name__)

_name_cache = Cache()
_name_server = client.createResolver(servers=[('8.8.8.8', 53)])
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


class RemoteProtocol(protocol.Protocol):

    def connectionMade(self):
        self.proxy.connectOk(self.transport)

    def dataReceived(self, data):
        self.proxy.recvRemote(data)


class RemoteFactory(protocol.ClientFactory):

    def __init__(self, proxy):
        self.protocol = RemoteProtocol
        self.proxy = proxy

    def buildProtocol(self, addr):
        p = protocol.ClientFactory.buildProtocol(self, addr)
        p.proxy = self.proxy
        return p

    def clientConnectionFailed(self, connector, reason):
        message = reason.getErrorMessage()
        self.proxy.connectErr(message)

    def clientConnectionLost(self, connector, reason):
        self.proxy.connectClosed()


class SockProxy:

    def __init__(self, sock_id, dispatcher, host, port):
        self.sock_id = sock_id
        self.dispatcher = dispatcher
        self.connected = False
        self.buffer = b''
        self.host = host
        self.port = port
        self.addr = None
        self.transport = None
        self.setAddr(host)

    def connectRemote(self):
        assert self.addr
        factory = RemoteFactory(self)
        reactor.connectTCP(
                self.addr,
                self.port,
                factory
        )
        self.connected = True

    def resolveOk(self, addr):
        self.addr = addr
        if not self.connected and len(self.buffer) > 0:
            self.connectRemote()

    def resolveErr(self):
        logger.error(
                'sock_id[%u] resolve host[%s] failed',
                self.sock_id,
                self.host
        )
        self.dispatcher.handleConnect(self.sock_id, 1)

    def setAddr(self, host):
        if _IP.match(host):
            self.addr = host
        else:
            try:
                self.addr = _name_cache[host]
            except KeyError:
                self.addr = None
                d = _name_server.lookupAddress(host)

                def resolve_ok(records, proxy):
                    answers, *_ = records
                    for answer in answers:
                        if answer.type != dns.A:
                            continue
                        addr = answer.payload.dottedQuad()
                        proxy.resolveOk(addr)
                        break
                    else:
                        proxy.resolveErr()

                d.addCallback(resolve_ok, self)

                def resolve_err(res, proxy):
                    proxy.resolveErr()

                d.addErrback(resolve_err, self)

    def connectOk(self, transport):
        if len(self.buffer) > 0:
            transport.write(self.buffer)
            self.buffer = b''
        self.transport = transport

    def connectErr(self, message):
        logger.error(
                'sock_id[%u] connect %s:%u failed[%s]',
                self.sock_id,
                self.host,
                self.port,
                message
        )
        self.dispatcher.handleConnect(self.sock_id, 1)

    def sendRemote(self, data):
        if self.transport is not None:
            self.transport.write(data)
            return
        self.buffer += data
        if not self.connected and self.addr is not None:
            self.connectRemote()

    def recvRemote(self, data):
        self.dispatcher.handleRemote(self.sock_id, data)

    def connectClosed(self):
        logger.info(
                'sock_id[%u] connection[%s:%u] closed',
                self.sock_id,
                self.host,
                self.port
        )
        self.dispatcher.handleClose(self.sock_id)

    def close(self):
        if self.transport:
            self.transport.loseConnection()


class SocksDispatcher:

    def __init__(self, transport):
        self.socks = {}
        self.transport = transport

    def dispatchMessage(self, message):
        type, = struct.unpack('!B', message[4:5])
        if 1 == type:
            self.connectRemote(message)
        elif 3 == type:
            self.sendRemote(message)
        elif 5 == type:
            self.closeRemote(message)
        else:
            logger.error('receive unknown message type=%u', type)

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
        host = message[13:-2].tobytes().decode('utf-8').strip()
        port, = struct.unpack('!H', message[-2:])
        logger.info(
                'sock_id[%u] connect %s:%u',
                sock_id,
                host,
                port
        )
        assert sock_id not in self.socks
        self.socks[sock_id] = SockProxy(sock_id, self, host, port)

    def handleConnect(self, sock_id, code):
        """
        type 2:
        +-----+------+----+------+
        | LEN | TYPE | ID | CODE |
        +-----+------+----+------+
        |  4  |   1  |  8 |   1  |
        +-----+------+----+------+
        """
        if 0 == code:
            return
        self.closeSock(sock_id)
        message = struct.pack(
                '!IBQB',
                14,
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
        |  4  |   1  |  8 |      |
        +-----+------+----+------+
        """
        sock_id, = struct.unpack('!Q', message[5:13])
        data = message[13:]
        try:
            sock = self.socks[sock_id]
        except KeyError:
            logger.error('send data to closed sock_id[%u]', sock_id)
            self.sendClose(sock_id)
        else:
            sock.sendRemote(data)

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
        except KeyError:
            logger.error('close closed sock_id[%u]', sock_id)
        else:
            sock.close()
            del self.socks[sock_id]

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
        logger.info('sock_id[%u] remote closed', sock_id)
        self.closeSock(sock_id)

    def sendClose(self, sock_id):
        message = struct.pack(
                '!IBQ',
                13,
                6,
                sock_id
        )
        self.transport.write(message)

    def handleClose(self, sock_id):
        """
        type 6:
        +-----+------+----+
        | LEN | TYPE | ID |
        +-----+------+----+
        |  4  |   1  |  8 |
        +-----+------+----+
        """
        if sock_id not in self.socks:
            return
        logger.info('sock_id[%u] local closed', sock_id)
        self.closeSock(sock_id)
        self.sendClose(sock_id)


class TunnelProtocol(protocol.Protocol):

    def connectionMade(self):
        self.buffer = b''
        self.dispatcher = SocksDispatcher(self.transport)

    def connectionLost(self, reason=None):
        logger.info('proxy closed connection')

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


def start_server(config):
    port = config['port']
    ca, key, cert = config['ca'], config['key'], config['cert']
    factory = protocol.ServerFactory()
    factory.protocol = TunnelProtocol
    ssl_ctx = SSLCtxFactory(
            False,
            ca,
            key,
            cert,
            verify
    )
    reactor.listenSSL(port, factory, ssl_ctx)
    logger.info('server start running...')
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
