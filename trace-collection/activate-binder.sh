#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <app uid>"
    exit 1
fi

U_ID=$1
BINDIR="/data/local/tmp"
UIDMONITOR="uidmonitor"
REFRESHER="refresher"

adb shell su 0 setenforce 0

adb shell "su 0 echo $U_ID > $BINDIR/$UIDMONITOR"
adb shell "su 0 $BINDIR/$REFRESHER"
adb shell "su 0 dmesg -C"
adb shell su 0 setenforce 1
