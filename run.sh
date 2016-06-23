#! /bin/bash

id socks5 &>/dev/null || {
	pip install --proxy http://103.55.27.122:8888 -r requirements.txt;
	adduser --disabled-password --gecos '' socks5;
}

echo "running socks5 proxy......"
su -m socks5 -c "python s5tun.py -S 103.55.27.122"
