#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <app package>"
    exit 1
fi

PACK=$1
adb shell dumpsys package $PACK | grep userId= | sed -E "s/^.*userId=([0-9]+)/\1/g"
