#!/usr/bin/env python3

import sys
import os
import os.path
import re
import pickle
from subprocess import Popen, PIPE

unfinished_syscall_re = re.compile(r"(.*) [<]?unfinished \.\.\.>.*$")
resumed_syscall_re = re.compile(r"^.*<\.\.\. ([\S]+) resumed>(.*)$")

def resume_syscall(beginning, ending):
    match = resumed_syscall_re.match(ending)
    if match is None: # the second one is not a resumed syscall
        return None
    (resumed_name, ends) = match.groups()

    match = unfinished_syscall_re.match(beginning)
    if match is None: # the first one is not an unfinished syscall
        return None
    unfinished = match.group(1)
    if resumed_name not in unfinished: # the syscall name don't match
        return None
    return unfinished + ends + "\n"

def is_unfinished(line):
    return unfinished_syscall_re.match(line)

def is_resumed(line):
    return resumed_syscall_re.match(line)

def main(strace_file):
    lines = sorted(strace_file.readlines()) ## sort by pid
    strace_file.close()
    new_content = []
    pending = None
    old_pid = None

    for cnt, line in enumerate(lines):
        pid = line.split(' ', 1)[0]
        if pid != old_pid:
            pending = None
        old_pid = pid
        if not pending:
            if is_unfinished(line):
                pending = line
            elif is_resumed(line):
                print("%d: %s -> resumed syscall but no pending one" %
                      (cnt, line),
                      file = sys.stderr)
            else:
                new_content.append(line)
        else:
            if is_resumed(line) and is_unfinished(line):
                continue
            elif is_resumed(line):
                complete = resume_syscall(pending, line)
                pending = None
                if complete == None:
                    continue
                new_content.append(complete)
            elif is_unfinished(line):
                if line.split()[0] != pending.split()[0]:
                    new_content.append(pending)
                    pending = line
                else:
                    print(("%d: unfinished syscall but there's a" +
                           " pending one\npending:%sfound:%s\n")
                      % (cnt, pending, line), file = sys.stderr)
            else:
                if "killed" in line:
                    new_content.append(pending)
                    new_content.append(line)
                else:
                    print(("%d: syscall pending but the next one is " +
                           "not completing it.\npending: %sfound: %s") %
                          (cnt, pending, line),
                          file = sys.stderr)

    new_content.sort(key=lambda x: float(x.split()[1])) ## sort by timestamp
    for line in new_content:
        print(line, end=('' if '\n' in line else ''))

if __name__ == "__main__":
    argc = len(sys.argv)
    if argc != 2:
        print("Usage %s <strace output>" % sys.argv[0])
        sys.exit(1)

    if not os.path.exists(sys.argv[1]):
        print("%s: file doesn't exist", sys.argv[1])
        sys.exit(1)

    main(open(sys.argv[1], "r"))
