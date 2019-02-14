# socks5 proxy

##  Server

### python3
python3 server.py -d --key keyfile --cert certfile --ca cafile

### docker
start-server.sh

## Client
python3 proxy.py -d --key keyfile --cert certfile --ca cafile
