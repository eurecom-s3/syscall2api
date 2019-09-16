#!/bin/bash

if [ "$#" -ne 1 ]; then
    OUT=apps-list
    rm apps-list 2> /dev/null
else
    OUT=$1
fi

ls -l apks | grep -v '.txt$' | awk '{print $9}' | tail -n +2 > $OUT
