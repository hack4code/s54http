#! /usr/bin/env bash


NAME="s5p"
GREP="grep"
DOCKER="docker"


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


if ($DOCKER container ls -a --format '{{.Names}}' | $GREP "$NAME" &>/dev/null)
then
	echo "rm container ..."
	$DOCKER container stop "$NAME"
	$DOCKER container rm "$NAME"
fi

if ($DOCKER image ls --format '{{.Repository}}' | $GREP "$NAME" &>/dev/null)
then
	echo "rm image ..."
	$DOCKER image rm "$NAME"
fi

echo "build image ..."
$DOCKER build -t $NAME .

echo "build $ROLE container ..."
if [[ "$ROLE" == "server" ]]; then
	$DOCKER create --restart=always --name $NAME -p 8080:8080 $NAME s5pserver
elif [[ "$ROLE" == "proxy" ]]; then
	$DOCKER create --restart=always --name $NAME -p 8080:8080 $NAME s5pproxy -l 0.0.0.0 -S $SERVER
else
	echo "only support server|proxy container"
	exit 1
fi
