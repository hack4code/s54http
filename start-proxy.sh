#! /usr/bin/env bash

[[ -f socks.pid ]] && ps -p $(cat socks.pid) | grep proxy &>/dev/null || {
	[[ -f socks.pid ]] && rm -f socks.pid
	python3 proxy.py -S "$1" -d
}
