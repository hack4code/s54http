#! /usr/bin/env bash

id socks5 &>/dev/null || {
	pip install -r requirements.txt;
	adduser --disabled-password --gecos '' socks5;
}
su -m socks5 -c "pypy3 server.py"
