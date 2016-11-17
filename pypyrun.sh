#! /bin/bash

id socks5 &>/dev/null || {
	pip install --proxy http://103.200.29.9:8888/ -r requirements.txt;
	adduser --disabled-password --gecos '' socks5;
}

echo "running socks5 proxy......"
su -m socks5 -c "pypy3 s5tun.py -S "
