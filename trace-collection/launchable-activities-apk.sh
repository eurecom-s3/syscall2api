#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <APK file>"
    exit 1
fi

APK=$1

if ! which aapt > /dev/null ; then
    echo "aapt not found"
    exit 3
fi

ACTIVITIES=$(aapt dump badging $APK | grep "launchable-activity" | \
		    sed "s/^.*name='\([^']*\)'.*$/\1/")
PACKAGE=$(aapt dump badging $APK | grep "^package:" | \
		 sed "s/^.*name='\([^']*\)'.*$/\1/")

for ACT in $ACTIVITIES ;
do
	   echo "$PACKAGE $ACT"
done
