#! /usr/bin/env bash


NAME="s5p"
GREP="grep"
DOCKER="docker"


if ($DOCKER container ls -a --format '{{.Names}}' | $GREP "$NAME" &>/dev/null)
then
	echo "rm container ..."
	$DOCKER container rm "$NAME"
fi

if ($DOCKER image ls --format '{{.Repository}}' | $GREP "$NAME" &>/dev/null)
then
	echo "rm image ..."
	$DOCKER image rm "$NAME"
fi

echo "build image ..."
$DOCKER build -t $NAME .
echo "build container ..."
$DOCKER run -d --restart=always --name $NAME -p 8080:8080 $NAME
