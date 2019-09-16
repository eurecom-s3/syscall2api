#!/bin/bash

APP=$1
DIR=$(dirname $0)
APP_NAME=$(echo $APP | sed 's/.apk$//g')
PERM=$(echo $APP | sed 's/apk$/txt/g')
cat $DIR/apks/$PERM | grep -v "^$APP_NAME$"
