#! /usr/bin/env python
# -*- coding: utf-8 -*-


import gc
import logging
import struct
import weakref

from twisted.application import internet as TwistedInetService
from twisted.internet import (
    endpoints as TwistedEndpoint,
    error as TwistedError,
    protocol as TwistedProtocol,
    reactor,
)

from s54http.utils import (
    daemonize,
    init_logger,
    NullProxy,
    parse_args,
    SSLCtxFactory,
)


logger = logging.getLogger(__name__)
config = {
    'daemon': False,
    'saddr': '',
    'sport': 8080,
    'host': '127.0.0.1',
    'port': 8080,
    'ca': 'keys/ca.crt',
    'key': 'keys/client.key',
    'cert': 'keys/client.crt',
    'dhparam': 'keys/dhparam.pem',
    'pidfile': 's5p.pid',
    'logfile': 'proxy.log',
    'loglevel': 'INFO'
}


class TunnelProtocol(TwistedProtocol.Protocol):

    def connectionMade(self):
        self.transport.setTcpNoDelay(True)
        self.transport.setTcpKeepAlive(True)
        self.buffer = b''
        self.dispatcher = self.factory.dispatcher
        self.dispatcher.tunnelConnected(self)
        server = self.transport.getPeer()
        logger.info(
            'proxy connected to %s:%u',
            server.host,
            server.port,
        )

    def dataReceived(self, data):
        self.buffer += data
        while True:
            if len(self.buffer) < 4:
                return
            length, = struct.unpack('!I', self.buffer[:4])
            if len(self.buffer) < length:
                return
            message = memoryview(self.buffer)[:length]
            self.dispatcher.dispatchMessage(message)
            self.buffer = self.buffer[length:]

    def connectionLost(self, reason):
        self.dispatcher.tunnelClosed()
        server = self.transport.getPeer()
        logger.info(
            'proxy connetion to %s:%u lost',
            server.host,
            server.port
        )


class TunnelFactory(TwistedProtocol.ClientFactory):

    protocol = TunnelProtocol

    def __init__(self, dispatcher):
        self.dispatcher = dispatcher


class SocksDispatcher:

    __slots__ = [
        'socks',
        'transport',
        'service',
        '__weakref__',
    ]

    def __init__(self, addr, port, ssl_ctx):
        self.socks = {}
        self.transport = None
        self.service = None
        self.connectTunnel(addr, port, ssl_ctx)

    @property
    def isConnected(self):
        transport = self.transport
        if transport is None:
            return False
        if isinstance(transport, NullProxy):
            return False
        return True

    def connectTunnel(self, addr, port, ssl_ctx):
        factory = TunnelFactory(self)
        wrapped = TwistedEndpoint.HostnameEndpoint(reactor, addr, port)
        endpoint = TwistedEndpoint.wrapClientTLS(ssl_ctx, wrapped)
        service = TwistedInetService.ClientService(endpoint, factory)

        def connected(p):
            pass

        def failed(f):
            logger.error(
                'connect has failed 3 times, proxy will keep connecting'
            )

        service.whenConnected(failAfterFailures=3).addCallbacks(
            connected,
            failed
        )
        self.service = service
        self.service.startService()

    def tunnelConnected(self, p):
        self.transport = p.transport

    def tunnelClosed(self):
        self.transport = NullProxy()
        if self.socks:
            old_socks = self.socks
            self.socks = {}
            for sock in old_socks.values():
                transport = sock.transport
                if transport is not None:
                    transport.abortConnection()
                    sock.transport = None
            del old_socks
        gc.collect()

    def stopDispatch(self):
        if self.transport is not None:
            self.closeTunnel()
            self.transport.loseConnection()
            self.transport = NullProxy()
        self.service.stopService()

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

    def dispatchMessage(self, message):
        type, = struct.unpack('!B', message[4:5])
        if 2 == type:
            self.handleConnect(message)
        elif 4 == type:
            self.handleRemote(message)
        elif 6 == type:
            self.handleClose(message)
        else:
            raise RuntimeError(f'receive unknown message type={type}')

    def connectRemote(self, sock, host, port):
        """
        type 1:
        +-----+------+----+------+------+
        | LEN | TYPE | ID | HOST | PORT |
        +-----+------+----+------+------+
        |  4  |   1  |  4 |      |   2  |
        +-----+------+----+------+------+
        """
        sock_id = sock.sock_id
        self.socks[sock_id] = sock
        host_length = len(host)
        total_length = 11 + host_length
        logger.info(
            'sock_id[%u] connect %s:%u',
            sock_id,
            host.decode('utf-8'),
            port,
        )
        message = struct.pack(
            f'!IBI{host_length}sH',
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
        |  4  |   1  |  4 |   1  |
        +-----+------+----+------+
        """
        sock_id, code = struct.unpack('!IB', message[5:10])
        if 0 == code:
            return
        logger.info('sock_id[%u] connect failed', sock_id)
        self.closeSock(sock_id, abort=True)

    def sendRemote(self, sock, data):
        """
        type 3:
        +-----+------+----+------+
        | LEN | TYPE | ID | DATA |
        +-----+------+----+------+
        |  4  |   1  |  4 |      |
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
        total_length = 9 + len(data)
        header = struct.pack(
            f'!IBI',
            total_length,
            3,
            sock_id,
        )
        self.transport.writeSequence([header, data])

    def handleRemote(self, message):
        """
        type 4:
        +-----+------+----+------+
        | LEN | TYPE | ID | DATA |
        +-----+------+----+------+
        |  4  |   1  |  4 |      |
        +-----+------+----+------+
        """
        sock_id, = struct.unpack(f'!I', message[5:9])
        data = message[9:]
        try:
            sock = self.socks[sock_id]
        except KeyError:
            logger.error('sock_id[%u] receive data after closed', sock_id)
        else:
            logger.debug(
                'sock_id[%u] receive data length=%u from %s:%u',
                sock_id,
                len(data),
                sock.remote_host,
                sock.remote_port
            )
            sock.transport.write(bytes(data))

    def closeRemote(self, sock):
        """
        type 5:
        +-----+------+----+
        | LEN | TYPE | ID |
        +-----+------+----+
        |  4  |   1  |  4 |
        +-----+------+----+
        """
        sock_id = sock.sock_id
        if sock_id not in self.socks:
            return
        logger.info('sock_id[%u] local closed', sock_id)
        self.closeSock(sock_id)
        message = struct.pack(
            '!IBI',
            9,
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
        |  4  |   1  |  4 |
        +-----+------+----+
        """
        sock_id, = struct.unpack('!I', message[5:])
        logger.info('sock_id[%u] remote closed', sock_id)
        self.closeSock(sock_id, abort=True)

    def closeTunnel(self):
        """
        type 7:
        +-----+------+
        | LEN | TYPE |
        +-----+------+
        |  4  |   1  |
        +-----+------+
        """
        message = struct.pack(
            '!IB',
            5,
            7
        )
        self.transport.write(message)


class Socks5Protocol(TwistedProtocol.Protocol):

    def connectionMade(self):
        dispatcher = self.factory.dispatcher
        self.dispatcher = weakref.proxy(dispatcher)
        self.remote_host = None
        self.remote_port = None
        self.state = 'waitHello'
        self.buffer = b''
        self.sock_id = self.factory.sock_id
        if not dispatcher.isConnected:
            self.transport.abortConnection()

    def connectionLost(self, reason):
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
            self.sendConnectReply(2)
            self.transport.loseConnection()
            return
        if reserved != 0:
            logger.error('reserved value not 0')
            self.sendConnectReply(2)
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
        self.sendConnectReply(0)
        self.remote_host = host.decode('utf-8').strip()
        self.remote_port = port
        self.buffer = b''
        self.state = 'sendRemote'
        self.dispatcher.connectRemote(self, host, port)

    def sendRemote(self, data):
        self.dispatcher.sendRemote(self, data)


class Socks5Factory(TwistedProtocol.ServerFactory):

    protocol = Socks5Protocol

    def __init__(self, address, port, ssl_ctx):
        self._sock_id = 0
        self.dispatcher = SocksDispatcher(
            address,
            port,
            ssl_ctx
        )

    def shutdown(self):
        self.dispatcher.stopDispatch()

    @property
    def sock_id(self):
        if 2**32 - 1 == self._sock_id:
            self._sock_id = 0
        self._sock_id = self._sock_id + 1
        return self._sock_id


def _create_ssl_context(config):

    def verify(conn, x509, errno, errdepth, ok):
        if not ok:
            cn = x509.get_subject().commonName
            raise RuntimeError(
                f'server certificate verify error[errno={errno} cn={cn}]',
            )
        return ok

    return SSLCtxFactory(
        True,
        config['ca'],
        config['key'],
        config['cert'],
        dhparam=config['dhparam'],
        callback=verify
    )


def serve(config):
    ssl_ctx = _create_ssl_context(config)
    address, port = config['host'], config['port']
    remote_addr, remote_port = config['saddr'], config['sport']
    factory = Socks5Factory(
        remote_addr,
        remote_port,
        ssl_ctx
    )

    def shutdown():
        logger.info('proxy stop running')
        factory.shutdown()

    reactor.addSystemEventTrigger(
        'before',
        'shutdown',
        shutdown
    )

    try:
        reactor.listenTCP(
            port,
            factory,
            interface=address
        )
    except TwistedError.CannotListenError:
        raise RuntimeError(
            f"couldn't listen on :{port}, address already in use"
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
    serve(config)


if __name__ == '__main__':
    main()
