#! /usr/bin/env bash

cd ~/Applications/s5p/

[[ -f s5tun.pid ]] && ps -p $(cat s5tun.pid) | grep s5tun &>/dev/null || {
	python3 s5tun.py -S "$1" -d
}
