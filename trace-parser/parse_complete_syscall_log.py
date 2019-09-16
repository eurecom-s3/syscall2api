#!/usr/bin/env python3

import sys
import os
import os.path
import datetime
import re
import time

## Api call entry example
#3 4437  11144708.218684 write(53</dev/null>, "S android.os.Parcel.readString()", 32) = 32
api_call_entry_re = re.compile(r"^([0-9]{1,6})\s+([0-9]+.[0-9]+)\s+write\(\d+<\/dev\/null>,\s+\"(S|E) ([^\"]+)\".*")

## Syscall entry example
## 2016  10018921.977124 munmap(0x75e917a000, 8192) = 0
syscall_entry_re = re.compile(r"^([0-9]{1,6})[ ]+([0-9]+.[0-9]+)[ ](.*)$")

def parse_datetime_syscalls(s):
    return float(s)

def parse_syscall_line(line):
    match = api_call_entry_re.match(line)
    if match is not None:
        (tid, date_time, type, api_call) = match.groups()
        date_time = parse_datetime_syscalls(date_time)
        return (date_time, "JAVA", tid, type, api_call)
    match = syscall_entry_re.match(line)
    if match is None:
        return None
    (tid, date_time, syscall) = match.groups()
    date_time = parse_datetime_syscalls(date_time)
    return (date_time, "SYSCALL", tid, syscall, "")


def read_syscalls(f):
    ret = []
    lines = f.readlines()
    flag = False
    pending = {}

    for line in lines:
        parsed = parse_syscall_line(line)
        if not parsed:
            print("Syscall line ignored: %s" % line, file=sys.stderr)
        else:
            ret += [parsed]

    if not all(ret[i][0] <= ret[i+1][0] for i in range(len(ret) - 1)):
        print("Sorting syscalls", file=sys.stderr)
        try:
            ret = sorted(ret)
        except:
            import IPython; IPython.embed()

    return ret

def main(syscalls_log):
    syscalls = read_syscalls(syscalls_log)
    print("%d syscalls" % len(syscalls), file=sys.stderr)

    events = syscalls
    events = sorted(events)
    for e in events:
        print('%f %s'%(e[0], ' '.join(e[1:])))
        # print('%s'%' '.join(e[1:]))

    syscalls_log.close()
    return


if __name__ == "__main__":
    argc = len(sys.argv)
    os.environ['TZ'] = "UTC-0"
    if argc == 2:
        if not os.path.exists(sys.argv[1]):
            print("%s: file doesn't exist", sys.argv[1])
            sys.exit(1)
        main(open(sys.argv[1], "r"))
    else:
        main(sys.stdin)    
