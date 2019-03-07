# -*- coding: utf-8 -*-


import os
import sys
import atexit
import signal
import logging
from pathlib import Path
from argparse import ArgumentParser
from collections import OrderedDict

from OpenSSL import SSL as ssl


__all__ = [
        'Cache',
        'SSLCtxFactory',
        'NullProxy',
        'daemonize',
        'init_logger',
        'parse_args',
]


logger = logging.getLogger(__name__)


class NullProxy:

    def __getattr__(self, name):
        return self

    def __call__(self, *args, **kwargs):
        return self


class SSLCtxFactory:

    method = ssl.TLSv1_2_METHOD
    _ctx = None

    def __init__(self, client, ca, key, cert):
        self.isClient = client
        self._ca = ca
        self._key = key
        self._cert = cert
        self.cacheContext()

    def _verify(self, conn, x509, errno, errdepth, ok):
        if not ok:
            if self.isClient:
                peer = 'server'
            else:
                peer = 'client'
            cn = x509.get_subject().commonName
            logger.error(
                    '%s verify failed errno=%d cn=%s',
                    peer,
                    errno,
                    cn
            )
        return ok

    def cacheContext(self):
        if self._ctx is not None:
            return
        ctx = ssl.Context(ssl.TLSv1_2_METHOD)
        ctx.set_options(ssl.OP_NO_SSLv2)
        ctx.set_options(ssl.OP_NO_SSLv3)
        ctx.set_options(ssl.OP_NO_TLSv1)
        ctx.set_options(ssl.OP_NO_TLSv1_1)
        ctx.use_certificate_file(self._cert)
        ctx.use_privatekey_file(self._key)
        ctx.check_privatekey()
        ctx.load_verify_locations(self._ca)
        ctx.set_verify(
                ssl.VERIFY_PEER |
                ssl.VERIFY_FAIL_IF_NO_PEER_CERT |
                ssl.VERIFY_CLIENT_ONCE,
                self._verify
        )
        self._ctx = ctx

    def __getstate__(self):
        d = self.__dict__.copy()
        del d['_ctx']
        return d

    def __setstate__(self, state):
        self.__dict__ = state

    def getContext(self):
        return self._ctx


class Cache(OrderedDict):

    def __init__(self, limit=1024):
        super().__init__()
        self.limit = limit

    def __setitem__(self, key, value):
        while len(self) >= self.limit:
            self.popitem(last=False)
        super().__setitem__(key, value)


def daemonize(pidfile, *,
              stdin='/dev/null',
              stdout='/dev/null',
              stderr='/dev/null'):
    if os.path.exists(pidfile):
        logger.error('already running')
        raise SystemExit(1)

    try:
        if os.fork() > 0:
            raise SystemExit(0)
    except OSError as e:
        raise RuntimeError(f'fork #1 failed: {e}')
    os.chdir('/')
    os.umask(0)
    os.setsid()

    try:
        if os.fork() > 0:
            raise SystemExit(0)
    except OSError as e:
        raise RuntimeError(f'fork #2 failed: {e}')

    sys.stdin.flush()
    sys.stdout.flush()

    with open(stdin, 'rb', 0) as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    with open(stdout, 'ab', 0) as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
    with open(stderr, 'ab', 0) as f:
        os.dup2(f.fileno(), sys.stderr.fileno())

    with open(pidfile, 'w') as f:
        print(os.getpid(), file=f)

    atexit.register(lambda: os.remove(pidfile))

    def sigterm_handler(signo, frame):
        os.remove(pidfile)
        raise SystemExit(1)

    signal.signal(signal.SIGTERM, sigterm_handler)


def init_logger(config, logger):
    level = config['loglevel']
    formatter = logging.Formatter(
        '%(asctime)s-%(levelname)s : %(message)s',
        '%Y-%m-%d %H:%M:%S'
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    logger.setLevel(level)
    logger.addHandler(handler)


def parse_args(config):
    usage = f"{sys.argv[0].split('/')[-1]}"
    parser = ArgumentParser(usage)
    parser.add_argument(
            "-d",
            "--daemon",
            dest="daemon",
            action="store_true",
            help="run as daemon"
    )
    parser.add_argument(
            "-l",
            "--host",
            dest="host",
            help="listen address"
    )
    parser.add_argument(
            "-p",
            "--port",
            dest="port",
            type=int,
            help="listen port"
    )
    parser.add_argument(
            "--key",
            dest="key",
            help="key file path"
    )
    parser.add_argument(
            "--ca",
            dest="ca",
            help="ca file path"
    )
    parser.add_argument(
            "--cert",
            dest="cert",
            help="cert file path"
    )
    parser.add_argument(
            "-S",
            dest="saddr",
            help="remote server address"
    )
    parser.add_argument(
            "-P",
            dest="sport",
            type=int,
            help="remote server port"
    )
    parser.add_argument(
            "--pidfile",
            dest="pidfile",
            help="pid file"
    )
    parser.add_argument(
            "--logfile",
            dest="logfile",
            help="log file"
    )
    parser.add_argument(
            "--loglevel",
            dest="loglevel",
            help="DEBUG, INFO, WARN, ERROR"
    )
    parser.add_argument(
            "--dns",
            dest="dns",
            help="dns server[addr:port|addr]"
    )
    args = parser.parse_args()
    for key in config.keys():
        value = getattr(args, key, None)
        if not value:
            continue
        config[key] = value
    for key in ('ca', 'key', 'cert', 'pidfile', 'logfile'):
        value = config[key]
        fp = Path(value)
        config[key] = str(fp.absolute())
        if key in ('ca', 'key', 'cert') and not fp.exists():
            raise RuntimeError(f'{key} file not existed')
