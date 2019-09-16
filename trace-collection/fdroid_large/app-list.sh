#!/bin/bash

if [ "$#" -ne 1 ]; then
    OUT=apps-list
    rm apps-list 2> /dev/null
else
    OUT=$1
fi

containsElement () {
    local e match="$1"
    shift
    for e; do [[ "$e" == "$match" ]] && return 0; done
    return 1
}

ALL_APPS=$(fdroidcl search | grep "^[^ ]" | awk "{print(\$1);}")
PERMISSIONS=$(cat permissions-list)

for APP in $ALL_APPS;
do
    PERMS=$(fdroidcl show $APP | grep Perms | \
		   awk -F ': ' '{print($2);}' | \
		   tr ', ' '\n' | grep -v "^$")
    for P in $PERMS;
    do
	if containsElement $P $PERMISSIONS -eq 1 ; then
	    echo $APP >> $OUT
	    break;
	fi;
    done;
done;
