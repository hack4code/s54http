# socks5 proxy

##  Server
s5pserver -d --key keyfile --cert certfile --ca cafile

## Client
s5pproxy -d --key keyfile --cert certfile --ca cafile


## Container
### build_container.sh server
### build_container.sh proxy 0.0.0.0
