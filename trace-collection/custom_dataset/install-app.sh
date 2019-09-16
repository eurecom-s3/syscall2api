#!/bin/bash
DIR=$(dirname $0)
adb install -r $DIR/apks/$1
