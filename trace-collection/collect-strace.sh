#!/bin/bash

if [ "$#" -ne 1 ]; then
    adb shell cat $STRACE_FILE
else
    adb pull $STRACE_FILE $1
fi
