import os
import sys
import logging
import stat
import fcntl
import getopt
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
    isClient = True
    method = ssl.TLSv1_2_METHOD
    _ctx = None

    def __init__(self, client, ca, capath, key, cert, verify):
        self.isClient = client
        self._ca = ca
        self._capath = capath
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
            ctx.load_verify_locations(self._ca, capath=self._capath)
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
    try:
        fd = os.open(pid_file, os.O_RDWR | os.O_CREAT,
                     stat.S_IRUSR | stat.S_IWUSR)
    except:
        logging.error('open pid-file %s failed', pid_file)
        sys.exit(-1)
    flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    flags |= fcntl.FD_CLOEXEC
    fcntl.fcntl(fd, fcntl.F_SETFD, flags)
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 0, 0, os.SEEK_SET)
    except IOError:
        old_pid = os.read(fd, 32)
        logging.error('already started at pid %d', old_pid)
        os.close(fd)
        sys.exit(-1)
    os.ftruncate(fd, 0)
    os.write(fd, str(pid).encode('utf8'))


def parse_args(args, config):
    shortopts = 'dp:k:a:c:S:P:r:'
    longopts = ['pid-file=', 'log-file=', 'log-level=']
    optlist, _ = getopt.getopt(args, shortopts, longopts)
    try:
        for k, v in optlist:
            if k == '-p':
                config['port'] = int(v)
            elif k == '-k':
                config['key'] = v
            elif k == '-c':
                config['cert'] = v
            elif k == '-a':
                config['ca'] = v
            elif k == '-r':
                config['capath'] = v
            elif k == '-S':
                config['server'] = v
            elif k == '-P':
                config['sport'] = int(v)
            elif k == '-d':
                config['daemon'] = True
            elif k == 'pid-file=':
                config['pid-file'] = v
            elif k == 'log-file=':
                config['log-file'] = v
            elif k == 'log-level=':
                config['log-level'] = log_level[v]
    except:
        logging.error('parse option %s error', k)
    if not config['daemon']:
        config['log-file'] = ''
