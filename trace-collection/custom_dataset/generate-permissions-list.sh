#!/bin/bash

if [ "$#" -ne 1 ]; then
    OUT=permissions-list
else
    OUT=$1
fi


adb shell pm list permissions -g -d | grep -v group | \
    grep permission | awk -F ':' "{print(\$2);}" | \
    awk -F '.' '{print $NF;}' > $OUT
