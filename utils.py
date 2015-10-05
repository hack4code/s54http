import os
import sys
import logging
from optparse import OptionParser
from collections import OrderedDict
from OpenSSL import SSL as ssl

log_level = {'debug': logging.DEBUG,
             'info': logging.INFO,
             'error': logging.ERROR}


class dns_cache(OrderedDict):
    def __init__(self, limit=None):
        super(dns_cache, self).__init__()
        self.limit = limit

    def __setitem__(self, key, value):
        while len(self) >= self.limit:
            self.popitem(last=False)
        super(dns_cache, self).__setitem__(key, value)


class ssl_ctx_factory:
    method = ssl.TLSv1_2_METHOD
    _ctx = None

    def __init__(self, client, ca, key, cert, verify):
        self.isClient = client
        self._ca = ca
        self._key = key
        self._cert = cert
        self._verify = verify
        self.cacheContext()

    def cacheContext(self):
        if self._ctx is None:
            ctx = ssl.Context(ssl.TLSv1_2_METHOD)
            ctx.set_options(ssl.OP_NO_SSLv2)
            ctx.use_certificate_file(self._cert)
            ctx.use_privatekey_file(self._key)
            ctx.check_privatekey()
            ctx.load_verify_locations(self._ca)
            ctx.set_verify(ssl.VERIFY_PEER |
                           ssl.VERIFY_FAIL_IF_NO_PEER_CERT |
                           ssl.VERIFY_CLIENT_ONCE,
                           self._verify)
            self._ctx = ctx

    def __getstate__(self):
        d = self.__dict__.copy()
        del d['_ctx']
        return d

    def __setstate__(self, state):
        self.__dict__ = state

    def getContext(self):
        return self._ctx


def daemon():
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    sys.stdin.close()


def write_pid_file(pid_file):
    pid = os.getpid()
    with open(pid_file, 'w') as fd:
        fd.write(str(pid))


def check_s5tun_config(config):
    if config['saddr'] == '':
        logging.error("socks5 proxy address is null")
        sys.exit(-1)


def parse_args(config):
    usage = "usage: %s [options]" % (sys.argv[0])
    parser = OptionParser(usage)
    parser.add_option("-d", "--daemon", dest="daemon",
                      action="store_true",
                      help="run app at backgroud")
    parser.add_option("-p", "--port", dest="port", type="int",
                      help="listen port")
    parser.add_option("-k", "--key", dest="key", type="string",
                      help="key file path")
    parser.add_option("-a", "--ca", dest="ca", type="string",
                      help="ca file path")
    parser.add_option("-c", "--cert", dest="cert", type="string",
                      help="cert file path")
    parser.add_option("-S", "--saddr", dest="saddr", type="string",
                      help="remote porxy address")
    parser.add_option("-P", "--sport", dest="sport", type="int",
                      help="remote proxy port")
    parser.add_option("-f", "--pidfile", dest="pidfile", type="string",
                      help="pid file path")
    parser.add_option("-l", "--logfile", dest="logfile", type="string",
                      help="log file path")
    parser.add_option("-e", "--loglevel", dest="loglevel", type="string",
                      help="log level [info, warn, error]")

    (options, args) = parser.parse_args()

    if options.port:
        config['port'] = options.port
    if options.key:
        config['key'] = options.key
    if options.cert:
        config['cert'] = options.cert
    if options.ca:
        config['ca'] = options.ca
    if options.saddr:
        config['saddr'] = options.saddr
    if options.sport:
        config['sport'] = options.sport
    if options.daemon:
        config['daemon'] = True
    if options.pidfile:
        config['pidfile'] = options.pidfile
    if options.logfile:
        config['logfile'] = options.logfile
    if options.loglevel:
        config['loglevel'] = log_level[options.loglevel]

    if not config['daemon']:
        config['logfile'] = ''
