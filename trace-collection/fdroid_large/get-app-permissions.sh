#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <app>" > /dev/stderr
    exit 1
fi;

PERMS=($(fdroidcl show $1 | grep Perms | head -1 | awk -F ':' '{print $2;}' |\
	       tr -d ' ' | tr ',' '\n'))

for PERM in ${PERMS[@]}
do
    if grep --silent -v '\.' <(echo $PERM) ; then
	echo "android.permission.$PERM"
    else
	echo "$PERM"
    fi
done
