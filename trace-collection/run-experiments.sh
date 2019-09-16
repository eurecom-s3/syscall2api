#!/bin/bash

if [ "$#" -ne 1 ] && [ "$#" -ne 2 ]; then
    echo "usage: $0 [--no-api-log] <app-collection>" > /dev/stderr
    exit 1
fi;

if [ "$#" -eq 2 ] && [ "$1" = "--no-api-log" ]; then
    ARG=$2
    LOG=0
elif [ "$#" -eq 2 ]; then
    echo "usage: $0 [--no-api-log] <app-collection>" > /dev/stderr
    exit 1
else
    ARG=$1
    LOG=1
fi;

if [ ! -f $ARG/apk-path.sh ] || [ ! -f $ARG/app-list.sh ] || \
       [ ! -f $ARG/generate-permissions-list.sh ] ; then
    echo "$ARG doesn't not contain the expected files" > /dev/stderr
    exit 1
fi;

PWD_VAR=$(pwd)

export OUT_DIR="/data/local/tmp"
export BINDER_FILE="$OUT_DIR/binder_trace"
export STRACE_FILE="$OUT_DIR/out"

if [ ! -f $ARG/permissions-list ] ; then
    cd $ARG
    ./generate-permissions-list.sh
    cd $PWD_VAR
fi;

if [ ! -f $ARG/apps-list ] ; then
    cd $ARG
    ./app-list.sh
    cd $PWD_VAR
fi;

APPS=($(cat $ARG/apps-list))
TIME=$(date +%F.%T)
TRACE_OUT_DIR=$(echo exp_$TIME)
mkdir $TRACE_OUT_DIR

for APP in ${APPS[@]}
do
    $ARG/install-app.sh $APP
    echo $ARG $APP
    APK_PATH=$($ARG/apk-path.sh $APP)
    if [[ $? -ne 0 ]]; then
	continue
    fi;
    echo $APK_PATH
    ACTIVITY=($(./launchable-activities-apk.sh $APK_PATH))

    # Grant permissions to the app
    PERMS=$($ARG/get-app-permissions.sh $APP)
    for PERM in $PERMS
    do
	adb shell pm grant ${ACTIVITY[0]} $PERM > /dev/null 2>/dev/null
    done;

    # Run the app for the first time without tracing it
    
    adb shell am start "${ACTIVITY[0]}/${ACTIVITY[1]}"
    sleep 10
    adb shell am force-stop "${ACTIVITY[0]}"

    echo $ACTIVITY
    # Run again with tracing enabled
    U_ID=$(./get-uid.sh "${ACTIVITY[0]}")
    ./activate-binder.sh "$U_ID"
    ./activate-strace.sh "${ACTIVITY[0]}"
    SKIP=0
    if [ "$LOG" -eq 1 ]; then
	./log-app.sh "${ACTIVITY[0]}" "${ACTIVITY[1]}"
	SKIP=$?
	adb shell "su 0 dmesg -w | grep 'FAZFAZFAZ' > $BINDER_FILE" &
	BINDER_LOG_PID=$!
    else
	./run-app.sh "${ACTIVITY[0]}" "${ACTIVITY[1]}"
    fi;

    if [[ $SKIP -eq 0 ]]; then
	read -t 300 -p "Hit ENTER to skip"
    fi;

    adb shell am force-stop "${ACTIVITY[0]}"
    kill -9 $BINDER_LOG_PID
    ./collect-strace.sh "$TRACE_OUT_DIR/${ACTIVITY[0]}_strace"
    ./collect-binder.sh "$TRACE_OUT_DIR/${ACTIVITY[0]}_binder"
    TMP=$(echo $APP | sed 's/.apk$//g')
    adb uninstall $TMP
done;
