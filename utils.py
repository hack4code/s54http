import os
import sys
import logging
import stat
import fcntl
import getopt


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


log_level = {'debug': logging.DEBUG,
             'info': logging.INFO,
             'error': logging.ERROR}


def parse_args(args, config):
    shortopts = 'dp:S:P:'
    longopts = 'pid-file='
    optlist, _ = getopt.getopt(args, shortopts, longopts)
    try:
        for k, v in optlist:
            if k == '-p':
                config['port'] = int(v)
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
