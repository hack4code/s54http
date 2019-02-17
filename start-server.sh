#! /usr/bin/env bash

NAME="s5p"
DOCKER="docker"
GREP="grep"

if !($DOCKER image ls --format '{{.Repository}}' | $GREP "$NAME" &>/dev/null)
then
	echo "build image ..."
	$DOCKER build -t $NAME .
fi

if !($DOCKER container ls -a --format '{{.Names}}' | $GREP "$NAME" &>/dev/null)
then
	echo "create container ..."
	$DOCKER run -d --restart=always --name $NAME -p 8080:8080 -v `pwd`/keys/:/s5p/keys/ $NAME
fi

if !($DOCKER container ls --format '{{.Names}}' | $GREP "$NAME" &>/dev/null)
then
	echo "start container ..."
	$DOCKER container start "$NAME"
fi
