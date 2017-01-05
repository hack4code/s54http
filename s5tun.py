#! /bin/env python


import logging
from twisted.internet import reactor, protocol

from utils import daemon, parse_args, mk_pid_file, ssl_ctx_factory, \
    check_s5tun_config, set_logger

config = {'daemon': False,
          'saddr': '',
          'sport': 6666,
          'port': 8080,
          'ca': 'keys/ca.crt',
          'key': 'keys/s5tun.key',
          'cert': 'keys/s5tun.crt',
          'pidfile': 's5tun.pid',
          'logfile': 's5tun.log',
          'loglevel': logging.DEBUG}

logger = logging.getLogger(__name__)


def verify_proxy(conn, x509, errno, errdepth, ok):
    if not ok:
        cn = x509.get_subject().commonName
        logger.error('socks5 proxy server verify failed: errno=%d cn=%s',
                     errno,
                     cn)
    return ok


class sock_remote_protocol(protocol.Protocol):
    def connectionMade(self):
        self.local_sock.remoteConnectionMade(self)

    def dataReceived(self, data):
        self.local_sock.transport.write(data)


class sock_remote_factory(protocol.ClientFactory):
    def __init__(self, sock):
        self.protocol = sock_remote_protocol
        self.local_sock = sock

    def buildProtocol(self, addr):
        p = protocol.ClientFactory.buildProtocol(self,
                                                 addr)
        p.local_sock = self.local_sock
        return p

    def clientConnectionFailed(self, connector, reason):
        logger.error('connect to socks5 proxy server failed: %s',
                     reason.getErrorMessage())
        self.local_sock.transport.loseConnection()

    def clientConnectionLost(self, connector, reason):
        logger.info('connetion to socks5 proxy server closed: %s',
                    reason.getErrorMessage())
        self.local_sock.transport.loseConnection()


class sock_local_factory(protocol.ServerFactory):
    def __init__(self, saddr, sport, ssl_ctx):
        self.saddr, self.sport = saddr, sport
        self.ssl_ctx = ssl_ctx
        self.protocol = sock_local_protocol

    def buildProtocol(self, addr):
        p = protocol.ServerFactory.buildProtocol(self,
                                                 addr)
        p.saddr, p.sport = self.saddr, self.sport
        p.ssl_ctx = self.ssl_ctx
        p.connectRemote()
        return p


class sock_local_protocol(protocol.Protocol):
    def __init__(self):
        self.state = 'waitRemote'
        self.buf = b''

    def dataReceived(self, data):
        method = getattr(self, self.state)
        method(data)

    def connectRemote(self):
        remote_factory = sock_remote_factory(self)
        reactor.connectSSL(self.saddr,
                           self.sport,
                           remote_factory,
                           self.ssl_ctx)

    def waitRemote(self, data):
        self.buf += data

    def sendRemote(self, data):
        self.remote_sock.transport.write(data)

    def remoteConnectionMade(self, sock):
        self.remote_sock = sock
        self.state = 'sendRemote'
        self.sendRemote(self.buf)
        self.buf = None


def run_server(config):
    port = config['port']
    saddr, sport = config['saddr'], config['sport']
    ca, key, cert = config['ca'], config['key'], config['cert']
    ssl_ctx = ssl_ctx_factory(True,
                              ca,
                              key,
                              cert,
                              verify_proxy)
    local_factory = sock_local_factory(saddr,
                                       sport,
                                       ssl_ctx)
    reactor.listenTCP(port,
                      local_factory)
    reactor.run()


def main():
    parse_args(config)
    set_logger(config,
               logger)
    check_s5tun_config(config)
    if config['daemon']:
        daemon()
    pid_file = config['pidfile']
    mk_pid_file(pid_file)
    run_server(config)

if __name__ == '__main__':
    main()
