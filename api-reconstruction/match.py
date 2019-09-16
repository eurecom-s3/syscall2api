import re
import pickle
import sys
from pathlib import Path

from analysis import symbols_generator, find_leaves_models, get_syscall_name
from analysis import prune_malloc_syscalls, list_remove_indexes, encode_trace
from analysis import load_trace, parse_lines, remove_noise

import analysis.classes as classes

from analysis.match_evaluation import *

debug = True

def remove_java_calls(traces):
    for trace in traces.values():
        to_remove = []
        for index, line in enumerate(trace):
            if 'JAVA' in line:
                to_remove.append(index)

        list_remove_indexes(trace, to_remove)

        if debug:
            for line in trace:
                assert 'JAVA' not in line, "%s should not conain JAVA" % line


def leaf_apis_in_trace(trace):
    ret = []
    for index, entry in enumerate(trace):
        if entry[0] != 'API' or entry[1] != 'S':
            continue
        flag = False
        for entry2 in trace[index+1:]:
            if entry2[0] == 'API':
                if entry2[2] == entry[2] and entry2[1] == 'E':
                    break
                flag = False
                break
            if entry2[0] == 'SYS':
                flag = True
        if flag:
            ret.append(entry)
    return ret


def separate_api_syscall(trace):
    i_max = len(trace)
    i = 0
    apis = []

    while i < i_max:
        if trace[i][0] == 'API':
            apis.append((i, trace[i]))
            del trace[i]
            i_max -= 1
            continue
        i += 1

    ret = []
    i = 0
    while i < len(apis):
        if apis[i][1][1] == 'S':
            j = i+1
            while j < len(apis):
                if apis[j][1][1] == 'E' and apis[i][1][2] == apis[j][1][2]:
                    ret.append((apis[i][0], apis[j][0], apis[j][1][2]))
                    break
                j += 1
        i += 1
    return ret


def remove_empty_apis(trace, models):
    to_remove = []

    for i, entry in enumerate(trace):
        if entry[0] == 'API':
            api = entry[2]
            if api not in models or models[api] is None:
                to_remove.append(i)

    list_remove_indexes(trace, to_remove)


def match(trace, models):
    ret = []
    encoded = encode_trace(trace)
    for api, model in models.items():
        for mod in model:
            m = mod.findall_trace_encoded(encoded)
            if m:
                ret += [(res.start(), res.end(), api) for res in m]
    return ret

def main(trace_fp):
    global apis, syscalls, threads, models, leaf_models, test_leaf
    models_file = 'models.pickle'
    symbols_file = 'symbols.pickle'

    print("Loading apis and syscalls lists")
    with open(symbols_file, 'rb') as pf:
        apis = pickle.load(pf)
        syscalls = pickle.load(pf)
    
    print("Loading models")
    with open(models_file, 'rb') as pf:
        models = pickle.load(pf)

    symbols_generator(apis | syscalls.keys())
    leaf_models = find_leaves_models(models, syscalls)

    threads = load_trace(trace_fp)
    threads = {tid: parse_lines(v) for (tid, v) in threads.items()}
    apis = {}
    test_leaf = {}
    for tid, trace in threads.items():
        remove_empty_apis(trace, models)
        l = len(trace)
        remove_noise(trace)
        test_leaf[tid] = leaf_apis_in_trace(trace)
        apis[tid] = separate_api_syscall(trace)

if __name__ == '__main__':
    argc = len(sys.argv)
    if argc < 2:
        print("Usage: %s <sys trace>" % sys.argv[0])
        sys.exit(1)
    if not Path(sys.argv[1]).is_file():
        print("%s: file not found" % sys.argv[1])
        sys.exit(1)

    with open(sys.argv[1], "r") as fp:
        main(fp)
