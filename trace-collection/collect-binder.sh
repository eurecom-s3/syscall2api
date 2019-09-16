#!/bin/bash

if [ "$#" -ne 1 ]; then
    adb shell cat $BINDER_FILE
else
    adb pull $BINDER_FILE $1
fi
