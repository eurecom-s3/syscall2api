#!/usr/local/bin/ipython3 -i

from analysis import *
import sys
from functools import reduce, lru_cache
from intervaltree import IntervalTree

def _match(trace, model, index, api):
    m = model.match_trace_encoded(trace[index:])
    if m is None:
        return None
    span = m.span()
    return (index, index+span[1], api)

def concat(l1, l2):
    l1 += l2
    return l1

def match_from_index(trace, models, index=0):
    all_matches = reduce(concat, [[_match(trace, m, index, api) for m in model]
                                  for api, model in models.items()])
    all_matches[:] = [x for x in all_matches if x is not None]
    if len(all_matches) == 0:
        return (None, None)
    all_matches.sort(reverse=True, key=lambda x: x[:-1])
    next_index = all_matches[0][1]
    best_matches = list(map(lambda x: x[2],
                            filter(lambda x: x[1] == next_index, all_matches)))
    return (next_index, best_matches)

def match_models(trace, models, matches, index=0):
    while index < len(trace):
        next_index, matches_number = match_from_index(trace, models, index)
        if next_index is None or next_index == index:
            index += 1
            continue
        matches[(index, next_index)] = matches_number
        index = next_index

def aggregate(matches, grade=None):
    lambdas = {None: lambda x: x,
               'PACK': get_api_package,
               'CLASS': get_api_class,
               'METHOD': get_api_method_name}
    for k, v in list(matches.items()):
        matches[k] = len(set(map(lambdas[grade], v)))

@persist("trace_analysis", (0, ))
def analysis(trace_file):
    traces = load_trace(trace_file)
    symbols_generator(apis | syscalls.keys())
    leaf_models = find_leaves_models(models, syscalls)
    matches = {}
    package_aggr = {}
    class_aggr = {}
    method_aggr = {}
    for tid, t in traces.items():
        print("TID: %d" % tid)
        first_api = trace_first_api(t)
        if first_api == -1:
            continue
        trace_remove_api_calls(t)
        t = trace_trim_syscalls(t)
        encoded = encode_trace(t)
        matches[tid] = {}
        match_models(encoded, leaf_models, matches[tid], first_api)
        package_aggr[tid] = dict(matches[tid])
        class_aggr[tid] = dict(matches[tid])
        method_aggr[tid] = dict(matches[tid])
        aggregate(package_aggr[tid], 'PACK')
        aggregate(class_aggr[tid], 'CLASS')
        aggregate(method_aggr[tid], 'METHOD')
        aggregate(matches[tid])
    ambiguity = {tid: int(reduce(lambda x,y: x*y, m.values(), 1))
                 for tid, m in matches.items()}
    package_amb = {tid: int(reduce(lambda x,y: x*y, m.values(), 1))
                 for tid, m in package_aggr.items()}
    class_amb = {tid: int(reduce(lambda x,y: x*y, m.values(), 1))
                 for tid, m in class_aggr.items()}
    method_amb = {tid: int(reduce(lambda x,y: x*y, m.values(), 1))
                 for tid, m in method_aggr.items()}
    return {'matches': matches,
            'ambiguity': ambiguity,
            'package_amb': package_amb,
            'class_amb': class_amb,
            'method_amb': method_amb}

def threads(trace_name):
    return list(analysis(trace_name)['matches'].keys())

class my_bool:
    def __init__(self, a = True):
        self._a = a
    def __bool__(self):
        self._a = not self._a
        return self._a

@persist("api_cov", (0, 1))
def compute_coverage(app_name, thread):
    trace = load_trace(app_name)[thread]
    span = trace_api_span(trace)
    a = my_bool()
    values = sorted({x: 1 if not a else 0
                     for x in reduce(lambda x, y: x + [y[0], y[1]],
                                     span, list())}.items())
    x_axis = list(map(lambda x: x[0], values))
    y_axis = list(map(lambda x: x[1], values))
    if len(x_axis) == 0:
        return None, None
    return x_axis, y_axis

def plot_api_coverage(app_name, thread):
    x_axis, y_axis = compute_coverage(app_name, thread)
    plt.plot(x_axis, y_axis, color='red', drawstyle='steps-post')

def bar_plot(app_name, thread):
    matches = analysis(app_name)['matches'][thread]
    tmp = {x[0]: y for x, y in matches.items()}
    keys = sorted(matches.keys())
    x_axis = [x[0] for x in keys]
    x_width = [x[1] - x[0] for x in keys]
    y_axis = [tmp[x] for x in x_axis]

    print("Matches")
    plt.bar(x_axis, y_axis, x_width)
    print("Coverage")
    plot_api_coverage(app_name, thread)
    plt.show()
    return

@lru_cache(maxsize=100)
def hit_miss(trace, thread):
    trr = load_trace(trace)[thread]
    trr = trace_trim_syscalls(trr)
    apis = trace_get_apis(trr)
    first = trace_first_api(trr)
    ms = {}
    enc = encode_trace(trr)
    match_models(enc, leaf_models, ms, first)
    (good, bad, nf, not_bad) = (0, 0, 0, 0)
    for (s, e, api) in apis:
        if (s, e) not in ms:
           nf += 1
           continue
        if api in ms[(s, e)]:
           good += 1
        elif api in leaf_models:
           bad += 1
        else:
           not_bad += 1
    return (good, bad, nf, not_bad, ms, apis)

def main(traces):
    res = {}
    for t in traces:
        print("Stating analysis of %s" % t)
        res[t] = analysis(t)
    for app in traces:
        print("Computing coverage of %s" % app)
        for thread in analysis(app)['matches'].keys():
            compute_coverage(app, thread)
    return res

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: %s <trace>" % sys.argv[0], file=sys.stderr)
        sys.exit(1)

    models = load_models("models2.pickle")
    apis, syscalls = load_symbols()
    symbols_generator(apis | syscalls.keys());
    leaf_models = find_leaves_models(models, syscalls)
    if any(x == None for x in (models, apis, syscalls)):
        sys.exit(1)

    results = main(sys.argv[1:])
