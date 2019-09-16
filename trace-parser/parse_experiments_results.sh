#!/bin/bash

TREE=""
if [ "$#" -ne 1 ]; then
    TREE="--no-tree"
    if [ "$#" -ne 2 ]; then
	echo "usage: $0 <results-directory> [--no-tree]"
	exit 1
    fi
fi

DIR=$1
CWD=$(pwd)
RESULT_FILES=$(find $DIR -not -empty -regex ".*_strace")

for FILE in $RESULT_FILES
do
    echo "Preporcessing syscall file$FILE"
    STRAIGHTENED_FILE=$FILE"_straight"
    if [ ! -f $STRAIGHTENED_FILE ]; then
	python3 straighten_strace.py $FILE > $STRAIGHTENED_FILE 2>/dev/null
    fi

    FULL_LOG=$FILE"_full"
    if [ ! -f $FULL_LOG ]; then
	python3 parse_complete_syscall_log.py $STRAIGHTENED_FILE\
		> $FULL_LOG 2>/dev/null
    fi
done;

BINDER_FILES=$(find $DIR -not -empty -regex ".*_binder")
for FILE in $BINDER_FILES
do
    echo "Preporcessing binder file $FILE"
    PARSED_FILE=$FILE"_parsed"
    if [ ! -f $PARSED_FILE ]; then
	python3 parse_service_trace.py $FILE > $PARSED_FILE
    fi;
done;


FULL_LOGS=($(find $DIR -not -empty -regex ".*_full"))
python3 read_full_log.py $TREE ${FULL_LOGS[@]} 2>/dev/null
