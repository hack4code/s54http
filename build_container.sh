#! /usr/bin/env bash
# vim: filetype=sh


NAME="s5p"


if (( $# < 1 )); then
  echo "usage: build_container.sh server | build_container.sh proxy server_address"
  exit 1
fi

ROLE="$1"

if [[ $ROLE == "proxy" ]]; then
  if (( $# < 2 )); then
    echo "usage: build_container.sh proxy server_address"
    exit 1
  fi
  SERVER="$2"
fi


if (docker container ls -a --format '{{.Names}}' | grep -q "$NAME")
then
  echo "rm container ..."
  docker container stop "$NAME"
  docker container rm "$NAME"
fi

if (docker image ls --format '{{.Repository}}' | grep -q "$NAME")
then
  echo "rm image ..."
  docker image rm "$NAME"
fi

echo "build image ..."
docker build -t $NAME .

echo "build $ROLE container ..."
if [[ "$ROLE" == "server" ]]; then
  docker create --restart=always --name $NAME --net=host $NAME s5pserver
elif [[ "$ROLE" == "proxy" ]]; then
  docker create --restart=always --name $NAME --net=host $NAME s5pproxy -S $SERVER
else
  echo "only support server|proxy container"
  exit 1
fi
