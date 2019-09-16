#!/usr/bin/env python3

import sys
import os
import os.path
import argparse
import re
import pickle
from collections import defaultdict
from subprocess import Popen, PIPE
from parse import *

def compute_trace_no_tree(trace, tid):
    print(("Processing trace for tid %s. " % tid) +
          ("Input lenght: %d" % len(trace)), file=sys.stderr)
    ret = {}
    stack = []
    calls = []
    current_api = "START"
    stack.append((current_api, calls))
    ## entry = (type, state (None for syscalls), API/SYSCALL name)
    for cnt, (type, state, name, timestamp) in enumerate(trace):
        current_api = stack[-1][0]
        calls = stack[-1][1]
        if type == "SYS":
            for (a, c) in stack:
                c.append(("SYS", name))
        elif type == "API" and state == "S":
            if current_api == 'START':
                ret['START'] = [calls]
                stack.pop()
            elif current_api == "NOAPI":
                if "NOAPI" not in ret:
                    ret["NOAPI"] = []
                if len(calls) != 0:
                    ret["NOAPI"].append(calls)
                stack.pop()
            stack.append((name, list()))
        elif type == "API" and state == "E":
            ## easy case: no need to unwind
            if name == current_api:
                stack.pop()
                if len(stack) == 0:
                    stack.append(("NOAPI", list()))
                if name not in ret:
                    ret[name] = list()
                ret[name].append(calls)
            elif name in ("START", "NOAPI"):
                continue
            else: ## unwind
                while name != current_api:
                    stack.pop()
                    if current_api not in ret:
                        ret[current_api] = list()
                    ret[current_api].append(calls)
                    if len(stack) == 0:
                        stack.append(("NOAPI", list()))
                        print("Stack totally unwinded", file=sys.stderr)
                        break
                    (current_api, calls) = stack[-1]

    print("Processing output stats. Different APIS: %d" % len(ret),
          file=sys.stderr)
    if None in ret:
        del ret[None]

    return ret

def compute_trace(trace, tid):
    print(("Processing trace for tid %s. " % tid) +
          ("Input lenght: %d" % len(trace)), file=sys.stderr)
    ret = {}
    stack = []
    calls = []
    current_api = "START"
    stack.append((current_api, calls))

    ## entry = (type, state (None for syscalls), API/SYSCALL name)
    for cnt, (type, state, name, timestamp) in enumerate(trace):
        (current_api, calls) = stack.pop()
        if type == "SYS":
            if calls is not None:
                calls.append(("SYS", name))
            stack.append((current_api, calls))

        elif type == "API" and state == "S":
            if current_api == 'START':
                ret['START'] = [calls]
                current_api = "NOAPI"
                calls = []
            elif current_api == "NOAPI":
                if "NOAPI" not in ret:
                    ret["NOAPI"] = []
                if len(calls) != 0:
                    ret["NOAPI"].append(calls)
                    calls = []

            stack.append((current_api, calls))
            if current_api not in ("NOAPI", "START"):
                try:
                    calls.append(("API", name))
                except:
                    import IPython
                    IPython.embed()

            current_api = name
            calls = []
            stack.append((name, calls))

        elif type == "API" and state == "E":
            if name != current_api:
                while True:
                    print("=================================", file=sys.stderr)
                    print("Warning: end of API %s not found.\n" % current_api +
                          "TID: %s Line: %d Timestamp:%s\n" %
                          (tid, cnt, timestamp) +
                          "APIs already parsed: %d" % len(ret),
                          file=sys.stderr)
                    print("=================================", file=sys.stderr)

                    if current_api not in ret:
                        ret[current_api] = []
                    ret[current_api].append(calls)

                    if len(stack) == 0:
                        print("=================================",
                              file=sys.stderr)
                        print(("TID: %s: while unwinding " +
                               "the stack, the starting point " +
                               "of %s was not found. Timestamp: %s. " +
                               "Is this the main thread?")
                              % (tid, name, timestamp), file=sys.stderr)
                        print("=================================",
                              file=sys.stderr)
                        stack.append(("NOAPI", []))
                        break

                    (current_api, calls) = stack[-1]
                    stack.pop()
                    if name == current_api:
                        break
                continue

            if name not in ret:
                ret[name] = []

            ret[name].append(calls)

    print("Processing output stats. Different APIS: %d" % len(ret),
          file=sys.stderr)
    if None in ret:
        del ret[None]

    return ret

def update_syscalls(syscalls, traces):
    for api in traces:
        for trace in traces[api]:
            if len(trace) == 0:
                continue
            syscalls_l = [x for (t, x) in trace if 'SYS' in t]
            for syscall in syscalls_l:
                syscall_name = syscall.split('(')[0]
                if syscall_name not in syscalls:
                    continue
                if api not in syscalls[syscall_name]:
                    syscalls[syscall_name].append(api)
            

def merge_api_traces(db, dicts):
    for trace in dicts:
        for api in trace.keys():
            if api not in db:
                db[api] = []
            for entry in trace[api]:
                db[api].append(entry)
    return db

def replace_ioctls(app, threads_syscalls):
    with open(app + "_binder_parsed", "r") as f:
        lines = f.readlines()

    threads_binder = defaultdict(list)
    for line in lines:
        tmp = parse_line(line)
        if tmp[0] is not None:
            threads_binder[tmp[0]].append(tmp)

    for thr, servs in threads_binder.items():
        if thr == "7492":
            with open("s_7518", "w") as fff:
                fff.write("\n".join([str(x) for x in threads_syscalls[thr]]))
        for serv in servs:
            (_, _, _, service, btime) = serv
            if thr not in threads_syscalls:
                continue
            sys_trace = list(threads_syscalls[thr])
            last_ioctl = -1
            for (index, (stype, _, spayload, stime)) in enumerate(sys_trace):
                if float(stime) > float(btime):
                    ## replace ioctl with service here
                    if last_ioctl != -1:
                        print("Yeah!", file=sys.stderr)
                        threads_syscalls[thr][last_ioctl] = serv[1:]
                    else:
                        print("TID: %s, BTimestamp: %s, STimestamp: %s, IOCTL for service %s not found" % (thr, btime, stime, service), file=sys.stderr)
                    break
                if stype != "SYS":
                    continue
                if binder_ioctl_re.match(spayload):
                    print("updated")
                    last_ioctl = index
        if thr == "7492":
            with open("e_7518", "w") as fff:
                fff.write("\n".join([str(x) for x in threads_syscalls[thr]]))


def main(db, syscalls, app_name, log_file, tree=True, services=False):
    print("Reading input file", file=sys.stderr)
    lines = log_file.readlines()
    log_file.close()
    threads_traces = {}
    api_syscalls_matches = []
    ct = compute_trace if tree else compute_trace_no_tree
    print("Passing over input file", file=sys.stderr)
    for line in lines:
        (tid, type, state, payload, timestamp) = parse_line(line)
        if tid is None:
            continue
        if tid not in threads_traces:
            threads_traces[tid] = []
        threads_traces[tid].append((type, state, payload, timestamp))

    if services:
        replace_ioctls(app_name, threads_traces)

    for tid, trace in threads_traces.items():
        trace = ct(trace, tid)
        api_syscalls_matches.append(trace)
        update_syscalls(syscalls, trace)

    print("Cleaning up traces", file=sys.stderr)
    merge_api_traces(db, api_syscalls_matches)


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("traces", type=str, nargs="+")
    parser.add_argument("--no-tree", action="store_true")
    parser.add_argument("--services", action="store_true")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    tree = not args.no_tree
    traces = args.traces
    services = args.services

    db, syscalls = load_db()
    if len(syscalls) == 0:
        syscalls_list = read_syscall_list()
        syscalls = {x: list() for x in syscalls_list}

    for arg in traces:
        print("Processing " + arg)
        if not os.path.exists(arg):
            print("%s: file doesn't exist" % arg)
            sys.exit(1)
        app_name = arg.split("_strace_full")[0]
        main(db,syscalls, app_name, open(arg, "r"), tree, services)

    store_db(db, syscalls)
