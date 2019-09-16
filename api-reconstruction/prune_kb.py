#!/usr/bin/env python3

import IPython
import pickle
import numpy as np
import matplotlib.pyplot as plt
import re
import stat
import sys
import os

from functools import reduce
from pathlib import Path

from analysis import prune_malloc_syscalls, prune_signal_handlings, noisy_syscalls


## Declaring global objects
d = None
syscalls = None
signal_regex = re.compile(r"--- SIG([^ ]+) .* ---")
return_regex = re.compile(r"rt_sigreturn")

def get_syscall_list_from_trace(trace):
    return [(t, x) for (t, x) in trace if 'SYS' in t]

def get_api_list_from_trace(trace):
    return [x for (t, x) in trace if 'API' in t]

def get_syscall_name(x): return x.split('(')[0]  # drop the paramenters

def remove_noise(trace):
    ret = []
    tmp = trace
    trace = prune_signal_handlings(prune_malloc_syscalls(trace))
    del tmp
    for entry in trace:
        if entry[0] == 'SYS':
            if get_syscall_name(entry[1]) in noisy_syscalls:
                continue
        ret.append(entry)
    return ret

def prune_kb(d):
    new_kb = {}
    apis = list(d.keys())
    for api in apis:
        traces = d[api]
        new_traces = []
        for trace in traces:
            new_traces.append(remove_noise(trace))
        new_kb[api] = new_traces
        del d[api]
        del traces
    return new_kb

if __name__ == '__main__':
    kb_file = "db.pickle"
    new_kb_file = 'pruned_db.pickle'

    if not Path(kb_file).is_file():
        print("Error: No KB file found", file=sys.stderr)
        sys.exit(1)

    with open(kb_file, "rb") as pf:
        d = pickle.load(pf)
        syscalls = pickle.load(pf)

    kb = prune_kb(d)
    del d

    with open(new_kb_file, "wb") as of:
        pickle.dump(kb, of)
        pickle.dump(syscalls, of)

