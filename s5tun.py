#! /usr/bin/env python


import logging
from twisted.internet import reactor, protocol

from utils import (
        daemonize, parse_args, ssl_ctx_factory, init_logger
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


def verify_proxy(conn, x509, errno, errdepth, ok):
    if not ok:
        cn = x509.get_subject().commonName
        logger.error(
                'socks5 proxy server verify failed: errno=%d cn=%s',
                errno,
                cn
        )
    return ok


class sock_remote_protocol(protocol.Protocol):

    def connectionMade(self):
        self.local_sock.remoteConnectionMade(self)

    def dataReceived(self, data):
        self.local_sock.transport.write(data)


class sock_remote_factory(protocol.ClientFactory):

    def __init__(self, sock):
        self.local_sock = sock
        self.protocol = sock_remote_protocol

    def buildProtocol(self, addr):
        p = protocol.ClientFactory.buildProtocol(self, addr)
        p.local_sock = self.local_sock
        return p

    def clientConnectionFailed(self, connector, reason):
        logger.error(
                'connect to socks5 proxy server failed: %s',
                reason.getErrorMessage()
        )
        self.local_sock.transport.loseConnection()

    def clientConnectionLost(self, connector, reason):
        logger.info(
                'connetion to socks5 proxy server closed: %s',
                reason.getErrorMessage()
        )
        self.local_sock.transport.loseConnection()


class sock_local_protocol(protocol.Protocol):

    def __init__(self):
        self.state = 'waitRemote'
        self.buf = b''
        self.remote_sock = None

    def connectionLost(self, reason=None):
        logger.info('local connection closed')
        if self.remote_sock is not None:
            logger.info('close remote connection')
            self.remote_sock.transport.loseConnection()

    def dataReceived(self, data):
        method = getattr(self, self.state)
        method(data)

    def waitRemote(self, data):
        self.buf += data

    def sendRemote(self, data):
        self.remote_sock.transport.write(data)

    def remoteConnectionMade(self, sock):
        self.remote_sock = sock
        self.state = 'sendRemote'
        self.sendRemote(self.buf)
        self.buf = None


class sock_local_factory(protocol.ServerFactory):

    def __init__(self, saddr, sport, ssl_ctx):
        self.saddr, self.sport = saddr, sport
        self.ssl_ctx = ssl_ctx
        self.protocol = sock_local_protocol

    def buildProtocol(self, addr):
        p = protocol.ServerFactory.buildProtocol(self, addr)
        remote_factory = sock_remote_factory(p)
        reactor.connectSSL(
                self.saddr,
                self.sport,
                remote_factory,
                self.ssl_ctx
        )
        return p


def start_server(config):
    port = config['port']
    saddr, sport = config['saddr'], config['sport']
    ca, key, cert = config['ca'], config['key'], config['cert']
    ssl_ctx = ssl_ctx_factory(
            True,
            ca,
            key,
            cert,
            verify_proxy
    )
    local_factory = sock_local_factory(saddr, sport, ssl_ctx)
    reactor.listenTCP(
            port,
            local_factory,
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
