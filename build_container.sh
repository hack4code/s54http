#! /usr/bin/env bash


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


if (docker container ls -a --format '{{.Names}}' | grep "$NAME" &>/dev/null)
then
	echo "rm container ..."
	docker container stop "$NAME"
	docker container rm "$NAME"
fi

if (docker image ls --format '{{.Repository}}' | grep "$NAME" &>/dev/null)
then
	echo "rm image ..."
	docker image rm "$NAME"
fi

echo "build image ..."
docker build -t $NAME .

echo "build $ROLE container ..."
if [[ "$ROLE" == "server" ]]; then
	docker create --restart=always --name $NAME -p 8080:8080 $NAME s5pserver
elif [[ "$ROLE" == "proxy" ]]; then
	docker create --restart=always --name $NAME -p 127.0.0.1:8080:8080 $NAME s5pproxy -l 0.0.0.0 -S $SERVER
else
	echo "only support server|proxy container"
	exit 1
fi
