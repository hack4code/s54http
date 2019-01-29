#! /usr/bin/env bash

SERVER=""

cd ~/Applications/s54http/

[[ -f s5tun.pid ]] && ps -p $(cat s5tun.pid) | grep s5tun &>/dev/null || {
	python3 s5tun.py -S $SERVER -d
}
