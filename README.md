# socks5 proxy

##  Server
s5pserver -d --key keyfile --cert certfile --ca cafile

## Client
s5pproxy -d -S server\_address --key keyfile --cert certfile --ca cafile


## Container
### ./build\_container.sh server
### ./build\_container.sh proxy server\_address
