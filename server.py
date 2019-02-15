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
_IP = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')


config = {
        'daemon': False,
        'port': 8080,
        'ca': 'keys/ca.crt',
        'key': 'keys/server.key',
        'cert': 'keys/server.crt',
        'pidfile': 'socks.pid',
        'logfile': 'socks.log',
        'loglevel': 'INFO',
        'dns': '8.8.8.8:53',
}


class RemoteProtocol(protocol.Protocol):

    def connectionMade(self):
        self.proxy = self.factory.proxy
        self.proxy.connectOk(self.transport)

    def dataReceived(self, data):
        self.proxy.recvRemote(data)


class RemoteFactory(protocol.ClientFactory):

    protocol = RemoteProtocol

    def __init__(self, proxy):
        self.proxy = proxy

    def clientConnectionFailed(self, connector, reason):
        message = reason.getErrorMessage()
        self.proxy.connectErr(message)

    def clientConnectionLost(self, connector, reason):
        self.proxy.connectionClosed()


class SockProxy:

    def __init__(self, sock_id, dispatcher, host, port):
        self.sock_id = sock_id
        self.dispatcher = dispatcher
        self.connected = False
        self.buffer = b''
        self.remote_host = host
        self.remote_addr = None
        self.remote_port = port
        self.transport = None
        self.resolveHost(host)

    def connectRemote(self):
        assert self.remote_addr
        factory = RemoteFactory(self)
        reactor.connectTCP(
                self.remote_addr,
                self.remote_port,
                factory
        )
        self.connected = True

    def resolveOk(self, addr):
        self.remote_addr = addr
        if not self.connected and len(self.buffer) > 0:
            self.connectRemote()

    def resolveErr(self):
        logger.error(
                'sock_id[%u] resolve host[%s] failed',
                self.sock_id,
                self.remote_host
        )
        self.dispatcher.handleConnect(self.sock_id, 1)

    def resolveHost(self, host):
        if _IP.match(host):
            self.remote_addr = host
        else:
            try:
                self.remote_addr = _name_cache[host]
            except KeyError:
                self.remote_addr = None
                d = lookup_addr(host)

                def resolve_ok(records, proxy):
                    answers, *_ = records
                    for answer in answers:
                        if answer.type != dns.A:
                            continue
                        addr = answer.payload.dottedQuad()
                        _name_cache[host] = addr
                        proxy.resolveOk(addr)
                        break
                    else:
                        proxy.resolveErr()

                d.addCallback(resolve_ok, self)

                def resolve_err(res, proxy):
                    proxy.resolveErr()

                d.addErrback(resolve_err, self)

    def connectOk(self, transport):
        transport.write(self.buffer)
        self.buffer = b''
        self.transport = transport

    def connectErr(self, message):
        logger.error(
                'sock_id[%u] connect %s:%u failed[%s]',
                self.sock_id,
                self.remote_host,
                self.remote_port,
                message
        )
        self.dispatcher.handleConnect(self.sock_id, 1)

    def sendRemote(self, data):
        if self.transport is not None:
            self.transport.write(data)
            return
        self.buffer += data
        if not self.connected and self.remote_addr is not None:
            self.connectRemote()

    def recvRemote(self, data):
        self.dispatcher.handleRemote(self.sock_id, data)

    def connectionClosed(self):
        logger.info(
                'sock_id[%u] connection[%s:%u] closed',
                self.sock_id,
                self.remote_host,
                self.remote_port
        )
        self.dispatcher.handleClose(self.sock_id)


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
        |  4  |   1  |  4 |      |   2  |
        +-----+------+----+------+------+
        """
        sock_id, = struct.unpack('!I', message[5:9])
        host = message[9:-2].tobytes().decode('utf-8').strip()
        port, = struct.unpack('!H', message[-2:])
        logger.info(
                'sock_id[%u] connect %s:%u',
                sock_id,
                host,
                port
        )
        assert sock_id not in self.socks
        self.socks[sock_id] = SockProxy(
                sock_id,
                self,
                host,
                port,
        )

    def handleConnect(self, sock_id, code):
        """
        type 2:
        +-----+------+----+------+
        | LEN | TYPE | ID | CODE |
        +-----+------+----+------+
        |  4  |   1  |  4 |   1  |
        +-----+------+----+------+
        """
        if 0 == code:
            return
        self.closeSock(sock_id, abort=True)
        message = struct.pack(
                '!IBIB',
                10,
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
        |  4  |   1  |  4 |      |
        +-----+------+----+------+
        """
        sock_id, = struct.unpack('!I', message[5:9])
        data = message[9:]
        try:
            sock = self.socks[sock_id]
        except KeyError:
            logger.error('sock_id[%u] send data after closed', sock_id)
        else:
            sock.sendRemote(data)

    def handleRemote(self, sock_id, data):
        """
        type 4:
        +-----+------+----+------+
        | LEN | TYPE | ID | DATA |
        +-----+------+----+------+
        |  4  |   1  |  4 |      |
        +-----+------+----+------+
        """
        total_length = 9 + len(data)
        header = struct.pack(
                '!IBI',
                total_length,
                4,
                sock_id,
        )
        self.transport.writeSequence([header, data])

    def closeSock(self, sock_id, *, abort=False):
        try:
            sock = self.socks[sock_id]
        except KeyError:
            logger.error('sock_id[%u] closed again', sock_id)
        else:
            del self.socks[sock_id]
            transport = sock.transport
            if transport is None:
                return
            if abort:
                transport.abortConnection()
            else:
                transport.loseConnection()

    def closeRemote(self, message):
        """
        type 5:
        +-----+------+----+
        | LEN | TYPE | ID |
        +-----+------+----+
        |  4  |   1  |  4 |
        +-----+------+----+
        """
        sock_id, = struct.unpack('!I', message[5:9])
        logger.info('sock_id[%u] remote closed', sock_id)
        self.closeSock(sock_id, abort=True)

    def handleClose(self, sock_id):
        """
        type 6:
        +-----+------+----+
        | LEN | TYPE | ID |
        +-----+------+----+
        |  4  |   1  |  4 |
        +-----+------+----+
        """
        if sock_id not in self.socks:
            return
        logger.info('sock_id[%u] local closed', sock_id)
        self.closeSock(sock_id)
        message = struct.pack(
                '!IBI',
                9,
                6,
                sock_id
        )
        self.transport.write(message)

    def tunnelClosed(self):
        if not self.socks:
            return
        old_socks = self.socks
        self.socks = {}
        for sock in old_socks.values():
            transport = sock.transport
            if transport is None:
                continue
            transport.abortConnection()


class TunnelProtocol(protocol.Protocol):

    def connectionMade(self):
        self.buffer = b''
        self.dispatcher = SocksDispatcher(self.transport)

    def connectionLost(self, reason=None):
        logger.info('proxy closed connection')
        self.dispatcher.tunnelClosed()

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


def lookup_addr(host):
    global resolver

    return resolver.lookupAddress(host)


def init_dns(config):
    global resolver

    conf = config['dns'].strip()
    if ':' in conf:
        addr, port = conf.split(':')
        port = int(port)
    else:
        addr = conf
        port = 53
    resolver = client.createResolver(servers=[(addr, port)])


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
    )
    reactor.listenSSL(port, factory, ssl_ctx)
    logger.info('server start running...')
    reactor.run()


def main():
    parse_args(config)
    init_logger(config, logger)
    init_dns(config)
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
