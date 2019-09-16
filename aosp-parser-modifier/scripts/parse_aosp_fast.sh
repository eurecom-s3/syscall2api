#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <path to AOSP>"
    exit 1
fi

AOSP_PATH=$1
BAK_SUFFIX=".bak"
cd ..
files=($(find $AOSP_PATH -regex ".*\.java" | grep -v "test" | \
	       grep -v "bench" | sort))

INDEX=0
LENGTH=120
LAST="${#files[@]}"

for (( INDEX=0; INDEX<LAST; INDEX=INDEX+LENGTH ));
do
    echo "${files[@]:$INDEX:$LENGTH}"
    java -jar AndroidLoggerCuncurrent.jar "${files[@]:$INDEX:$LENGTH}"
done


# java -jar AndroidLoggerCuncurrent.jar "$files[@]"
