#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <path to AOSP>"
    exit 1
fi

AOSP_PATH=$1
BAK_SUFFIX=".bak"
cd ..
files=$(find $AOSP_PATH -regex ".*\.java" | grep -v "test" | \
	       grep -v "bench" | sort)

for file in $files
do
    echo "Parsing $file"
    bak_file="$file$BAK_SUFFIX"
    cp $file $bak_file
    java -jar AndroidLogger.jar < $bak_file > $file 2> /dev/null
    rm $bak_file
done
