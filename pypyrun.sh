#! /bin/bash

id socks5 &>/dev/null || {
	pip install --proxy -r requirements.txt;
	adduser --disabled-password --gecos '' socks5;
}

echo "running socks5 proxy......"
su -m socks5 -c "pypy3 s5tun.py -S "
