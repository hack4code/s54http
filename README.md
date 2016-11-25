
# Run

##  Server
s54http.py -d -k keyfile -c certfile -a cafile

## Client

### s5tun.py
s5tun.py -d -k keyfile -c certfile -a ca file

### socat
socat tcp4-listen:xxxx,fork openssl:x.x.x.x:xxxx,cafile=,capath=,key=,cipher=AES256-GCM-SHA384

# Docker

## Images
docker pull pypy:3

## Run
docker run -v `pwd`:/s5px -w /s5px -p 8080:8080 -d pypy:3 ./pypyrun.sh
