#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <app package>"
    exit 1
fi

PACK=$1
OUT="$STRACE_FILE"

adb shell su 0 setenforce 0

adb shell mkdir -p $OUT_DIR
adb shell chmod 777 $OUT_DIR
adb shell touch $OUT
adb shell rm $OUT
adb shell touch $OUT
adb shell setprop wrap.$PACK "logwrapper strace -s 128 -f -y -yy -ttt -o $OUT"

adb shell su 0 setenforce 1
