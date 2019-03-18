#! /usr/bin/env python
# -*- coding: utf-8 -*-


import re
import gc
import struct
import logging
import weakref

from twisted.names import client, dns
from twisted.internet import reactor, protocol
from twisted.internet.error import CannotListenError

from s54http.utils import (
        SSLCtxFactory, Cache, NullProxy,
        daemonize, parse_args, init_logger,
)


logger = logging.getLogger(__name__)
config = {
        'daemon': False,
        'host': '0.0.0.0',
        'port': 8080,
        'ca': 'keys/ca.crt',
        'key': 'keys/server.key',
        'cert': 'keys/server.crt',
        'dhparam': 'keys/dhparam.pem',
        'pidfile': 's5p.pid',
        'logfile': 'server.log',
        'loglevel': 'INFO',
        'dns': None,
}
_IP = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')


class RemoteProtocol(protocol.Protocol):

    def connectionMade(self):
        self.proxy = self.factory.proxy
        try:
            self.proxy.connectOk(self.transport)
        except ReferenceError:
            self.transport.abortConnection()

    def dataReceived(self, data):
        try:
            self.proxy.recvRemote(data)
        except ReferenceError:
            self.transport.abortConnection()


class RemoteFactory(protocol.ClientFactory):

    protocol = RemoteProtocol

    def __init__(self, proxy):
        self.proxy = proxy

    def clientConnectionFailed(self, connector, reason):
        message = reason.getErrorMessage()
        try:
            self.proxy.connectErr(message)
        except ReferenceError:
            pass

    def clientConnectionLost(self, connector, reason):
        try:
            self.proxy.connectionClosed()
        except ReferenceError:
            pass


class SockProxy:

    def __init__(self, sock_id, dispatcher, host, port):
        self.sock_id = sock_id
        self.dispatcher = dispatcher
        self.remote_host = host
        self.remote_port = port
        self.resolver = dispatcher.resolver
        self.addr_cache = dispatcher.addr_cache
        self.buffer = b''
        self.has_connect = False
        self.remote_addr = None
        self.transport = None
        self.resolveHost(host)

    @property
    def isConnected(self):
        transport = self.transport
        if transport is None:
            return False
        if isinstance(transport, NullProxy):
            return False
        return True

    def close(self, *, abort=True):
        self.dispatcher = NullProxy()
        self.buffer = b''
        self.resolver = None
        self.remote_addr = None
        self.remote_host = None
        self.remote_port = None
        if self.transport:
            if abort:
                self.transport.abortConnection()
            else:
                self.transport.loseConnection()
        self.transport = NullProxy()

    def connectRemote(self):
        factory = RemoteFactory(weakref.proxy(self))
        reactor.connectTCP(
                self.remote_addr,
                self.remote_port,
                factory
        )
        self.has_connect = True

    def resolveOk(self, records):
        answers = records[0]
        for answer in answers:
            if answer.type != dns.A:
                continue
            addr = answer.payload.dottedQuad()
            self.addr_cache[self.remote_host] = addr
            self.remote_addr = addr
            break
        else:
            self.resolveErr('no ipv4 address found')
            return
        if not self.has_connect and len(self.buffer) > 0:
            self.connectRemote()

    def resolveErr(self, reason=''):
        logger.error(
                'sock_id[%u] resolve host[%s] failed[%s]',
                self.sock_id,
                self.remote_host,
                reason
        )
        self.dispatcher.handleConnect(self.sock_id, 1)

    def resolveHost(self, host):
        if _IP.match(host):
            self.remote_addr = host
        else:
            try:
                self.remote_addr = self.addr_cache[host]
            except KeyError:
                # getHostByName can't be used here, it may return ipv6 address
                self.resolver.lookupAddress(
                        host
                ).addCallbacks(
                        self.resolveOk,
                        self.resolveErr
                )

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
        if self.isConnected:
            self.transport.write(data)
            return
        self.buffer += data
        if not self.has_connect and self.remote_addr is not None:
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

    def __init__(self, p):
        self.socks = {}
        self.transport = p.transport
        self.resolver = p.factory.resolver
        self.addr_cache = p.factory.addr_cache

    def dispatchMessage(self, message):
        type, = struct.unpack('!B', message[4:5])
        if 1 == type:
            self.connectRemote(message)
        elif 3 == type:
            self.sendRemote(message)
        elif 5 == type:
            self.closeRemote(message)
        elif 7 == type:
            self.closeTunnel()
        else:
            raise RuntimeError(f'receive unknown message type={type}')

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
            logger.error('sock_id[%u] receive data after closed', sock_id)
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
            sock.close(abort=abort)
            del self.socks[sock_id]

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

    def closeTunnel(self):
        """
        type 7:
        +-----+------+
        | LEN | TYPE |
        +-----+------+
        |  4  |   1  |
        +-----+------+
        """
        proxy = self.transport.getPeer()
        logger.info(
                'proxy[%s:%s] closed tunnel',
                proxy.host,
                proxy.port
        )
        self.transport.loseConnection()

    def tunnelClosed(self):
        self.transport = NullProxy()
        for sock in self.socks.values():
            sock.close(abort=True)
        self.socks = {}
        gc.collect()


class TunnelProtocol(protocol.Protocol):

    def connectionMade(self):
        self.transport.setTcpNoDelay(True)
        self.transport.setTcpKeepAlive(True)
        self.buffer = b''
        self.dispatcher = SocksDispatcher(self)
        proxy = self.transport.getPeer()
        logger.info(
                'proxy[%s:%s] connected to server',
                proxy.host,
                proxy.port
        )

    def connectionLost(self, reason=None):
        proxy = self.transport.getPeer()
        logger.info(
                'proxy[%s:%s] lost connection',
                proxy.host,
                proxy.port
        )
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


def create_resolver(config):
    dns = config['dns']
    if dns is None:
        servers = None
    else:
        dns = dns.strip()
        if not dns:
            servers = None
        elif ':' in dns:
            addr, port = dns.split(':')
            servers = [(addr, int(port))]
        else:
            servers = [(dns, 53)]
    return client.createResolver(servers=servers)


def serve(config):
    addr, port = config['host'], config['port']
    ca, key, cert = config['ca'], config['key'], config['cert']
    dhparam = config['dhparam']
    factory = protocol.ServerFactory()
    factory.protocol = TunnelProtocol
    factory.resolver = create_resolver(config)
    factory.addr_cache = Cache()

    def verify(conn, x509, errno, errdepth, ok):
        if not ok:
            cn = x509.get_subject().commonName
            logger.info(
                    'proxy certificate verify error[errno=%d cn=%s]',
                    errno,
                    cn
            )
        return ok

    ssl_ctx = SSLCtxFactory(
            False,
            ca,
            key,
            cert,
            dhparam=dhparam,
            callback=verify
    )
    try:
        reactor.listenSSL(
                port,
                factory,
                ssl_ctx,
                interface=addr,
        )
    except CannotListenError:
        raise RuntimeError(
                f"couldn't listen on :{port}, address already in use"
        )
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
    serve(config)


if __name__ == '__main__':
    main()
