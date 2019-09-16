#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "$0 <package-name>"
else
    APK_CACHE=~/.cache/fdroidcl/apks
    FILES=($(ls -t $APK_CACHE | grep $1 | grep -v apk\.etag))
    if [ "${#FILES[@]}" -eq "0" ]; then
	echo "Can't find apk for $1" > /dev/stderr
	exit 1
    fi;
    if [ "${#FILES[@]}" -gt "1" ]; then
	echo "More than one file matches $1" > /dev/stderr
    fi;
    echo "$APK_CACHE/${FILES[0]}"
fi
