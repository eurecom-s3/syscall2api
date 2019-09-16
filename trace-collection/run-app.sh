#!/bin/bash -x

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <app package> <activity>"
    exit 1
fi

adb logcat -c
adb logcat -G 50M
#adb shell monkey -p $1 -c android.intent.category.LAUNCHER 1
adb shell am start -n $1/$2 -a android.intent.action.MAIN -c android.intent.category.LAUNCHER
# adb shell am start $1/$2
