# socks5 proxy

##  Server

### python3
python3 server.py -d -k keyfile -c certfile -a cafile

### docker
start-server.sh

## Client
python3 proxy.py -d -k keyfile -c certfile -a ca file
