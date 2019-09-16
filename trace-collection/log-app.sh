#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <app package> <activity>"
    exit 1
fi

adb logcat -c
adb logcat -G 50M
adb shell su root chmod 777 /data /data/local /data/local/tmp
adb shell su root touch /data/local/tmp/err
adb shell su root chmod 777 /data/local/tmp/err
LAUNCH=$(adb shell am start --ez apilog true -n $1/$2 -a android.intent.action.MAIN -c android.intent.category.LAUNCHER)
if [[ $LAUNCH == *"does not exist"* ]]; then
    exit 1
fi

# adb shell am start --ez apilog true $1/$2
