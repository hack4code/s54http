#! /usr/bin/env bash

[[ -f socks.pid ]] && ps -p $(cat socks.pid) | grep proxy &>/dev/null || {
	[[ -f socks.pid ]] && rm -f socks.pid
	python3 s54http/proxy.py -S "$1" -d
}
