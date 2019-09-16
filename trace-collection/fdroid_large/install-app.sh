#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "$0 <app-name>" > /dev/stderr
    exit 1
fi

fdroidcl download $1
APP_FILE=$(fdroid_large/apk-path.sh $1)
adb install $APP_FILE
# fdroidcl install $1
