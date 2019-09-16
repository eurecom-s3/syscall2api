import pickle, shelve
from pathlib import Path
import sys, re

def load_kb(kb_file='kb_no_empties.pickle'):
    if not Path(kb_file).is_file():
        print("Error: No KB file found", file=sys.stderr)
        return

    with open(kb_file, "rb") as pf:
        d = pickle.load(pf)
        syscalls = pickle.load(pf)
    return d, syscalls

def load_symbols(symbols_file = 'symbols.pickle'):
    if not Path(symbols_file).is_file():
        print("Error: No symbols file found", file=sys.stderr)
        return None, None

    with open(symbols_file, "rb") as pf:
        apis = pickle.load(pf)
        syscalls = pickle.load(pf)

    return apis, syscalls

def load_models(models_file = 'models.pickle'):
    if not Path(models_file).is_file():
        print("Error: No models file found", file=sys.stderr)
        return

    with open(models_file, 'rb') as pf:
        models = pickle.load(pf)

    return models

def load_compact_traces(traces_file='compact.trace'):
    if not Path(traces_file).is_file():
        print("Error: No traces file found", file=sys.stderr)
        return

    with open(traces_file, 'rb') as pf:
        traces = pickle.load(pf)

    return traces

def load_cache(filename):
    return shelve.open(filename, flag='c')

split_api_regex = re.compile(r"([^.]+)\.")
def dump_to_file(struct, f):
    fp = open(f, "wb")
    pickle.dump(struct, fp)
    fp.close()

def list_remove_indexes(l, i):
    for entry in i[::-1]:
        del l[entry]

def get_syscall_list_from_trace(trace):
    return [(t, x) for (t, x) in trace if 'SYS' in t]

def get_api_list_from_trace(trace):
    return [x for (t, x) in trace if 'API' in t]

def get_syscall_name(x): return x.split('(')[0]  # drop the paramenters

def get_api_method_name(api):
    return api.split('(')[0].split('.')[-1]

def get_api_class(api):
    return '.'.join([x.groups()[0] for x in split_api_regex.finditer(api)])

def get_api_package(api):
    return '.'.join([x.groups()[0] for x in
                     split_api_regex.finditer(api)][:-1])

def prune_syscalls_args(trace):
    ret = []
    for call in trace:
        if call[0] == 'SYS':
            ret.append((call[0], get_syscall_name(call[1])))
        else:
            ret.append(call)
    return ret


def tupletostring(t):
    return '_'.join(str(x) for x in t)

def read_trace_file(fp, threads=True):
    if threads:
        return read_trace_file_threads(fp)
    return fp.readlines()

## Return a dictionary with a trace (list of strings) for each thread
def read_trace_file_threads(fp):
    trace_entry_re = re.compile(r"^[\d\.]+\s[A-Z]+\s(\d{1,6})\s.*$")

    threads = {}
    lines = fp.readlines()
    for line in lines:
        m = trace_entry_re.match(line)
        if m:
            t = int(m.groups()[0])
            if t not in threads:
                threads[t] = []
            threads[t].append(line)
    return threads

syscall_entry_re = re.compile(r"^(.*)SYSCALL\s([\d]{1,6})\s(.*)$")
api_call_entry_re = re.compile(r"^(.*)(ANDROID|JAVA)\s(\d{1,6})\s(S|E)\s(.*)$")
def parse_lines(trace, time_flag=False):
    ret = []
    for line in trace:
        m = syscall_entry_re.match(line)
        if m:
            (time, tid, syscall) = m.groups()
            entry = ("SYS", syscall) if not time_flag else ("SYS",
                                                            float(time),
                                                            syscall)
            ret.append(entry)
            continue
        m = api_call_entry_re.match(line)
        if m:
            (time, _, _, state, api) = m.groups()
            entry = ("API", state, api) if not time_flag else ("API",
                                                               float(time),
                                                               state, api)
            ret.append(entry)

    assert len(ret) == len(trace)
    return ret

def load_trace(path, threads=True, time=False):
    if not Path(path).is_file():
        print("%s is not a valid file" % path, file=sys.stderr)
        return
    with open(path, "r") as fp:
        trace = read_trace_file(fp, threads)
    if threads:
        return {tid: parse_lines(trace, time) for tid, trace in trace.items()}
    else:
        return parse_lines(trace, time)

## In place remove futex and madvise syscall from a trace
def remove_noise(trace):
    to_remove = []
    for i, entry in enumerate(trace):
        if (entry[0] == 'SYS'
            and get_syscall_name(entry[1]) in ('futex', 'madvise')):
            to_remove.append(i)

    list_remove_indexes(trace, to_remove)
    pruned = prune_malloc_syscalls(trace)
    ## This is to do everything in place, though it's very ugly
    for i in range(len(trace)-1, 0, -1):
        del trace[i]
    trace += pruned

def trace_remove_api_calls(trace):
    trace[:] = filter(lambda x: x[0] != 'API', trace)

def stack_remove_api(stack, api):
    while True:
        if len(stack) == 0:
            return
        (n, entry) = stack.pop()
        if api == entry:
            break

def trace_api_span(trace):
    stack = list()
    covered = list()
    napi = 0
    for n, t in enumerate(trace):
        if t[0] == 'API':
            if t[1] == 'S':
                if len(stack) == 0:
                    covered.append((n - napi, n - napi))
                stack.append((n, t[2]))
            elif t[1] == 'E':
                stack_remove_api(stack, t[2])
            napi += 1
        elif len(stack) != 0:
            covered[-1] = (covered[-1][0], covered[-1][1] + 1)
    trace_remove_api_calls(trace)
    return list(filter(lambda x: x[0] != x[1], covered))

def trace_get_apis(trace):
    tmp = {}
    index = 0
    ret = []
    for call in trace:
        if call[0] == 'SYS':
            index += 1
            continue
        if call[0] == 'API':
            state = call[1]
            api = call[2]
            if state == 'S':
                if api not in tmp:
                    tmp[api] = []
                tmp[api].append(index)
            else:
                if api not in tmp:
                    continue
                start = tmp[api].pop()
                end = index
                ret.append((start, end, api))
    trace_remove_api_calls(trace)
    return list(filter(lambda x: x[0] != x[1], ret))

def trace_first_api(trace):
    for index, entry in enumerate(trace):
        if entry[0] == 'API':
            return index
    return -1
