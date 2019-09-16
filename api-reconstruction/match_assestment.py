#!/usr/local/bin/ipython3 -i

from analysis import *
import sys, os
from functools import reduce, lru_cache
from collections import defaultdict
from intervaltree import IntervalTree
from multiprocessing import Pool
import pickle

def _match(trace, model, index, api):
    m = model.match_trace_encoded(trace[index:])
    if m is None:
        return None
    span = m.span()
    return (index, index+span[1], api)

def concat(l1, l2):
    l1 += l2
    return l1

def match_from_index(trace, sys_models, index=0):
    models = sys_models[trace[index]]
    all_matches = []
    longest_match = 0
    for api, model in models.items():
        for m in model:
            ml = m.max_lenght()
            if ml != 0 and ml < longest_match:
                continue
            mtch = _match(trace, m, index, api)
            if mtch:
                all_matches += [mtch]
                l = mtch[1] - mtch[0]
                if l > longest_match:
                    longest_match = l
            
    if len(all_matches) == 0:
        return (None, None)
    all_matches.sort(reverse=True, key=lambda x: x[:-1])
    next_index = all_matches[0][1]
    best_matches = list(map(lambda x: x[2],
                            filter(lambda x: x[1] == next_index, all_matches)))
    return (next_index, best_matches)

def match_models(trace, models, matches, index=0):
    sys_models = defaultdict(lambda:defaultdict(list))
    for api, ms in models.items():
        for m in ms:
            sys_models[symbols_generator()[1][m.first_entry()]][api].append(m)
    while index < len(trace):
        next_index, matches_number = match_from_index(trace, sys_models, index)
        if next_index is None or next_index == index:
            index += 1
            continue
        matches[(index, next_index)] = matches_number
        index = next_index

def analysis(trace):
    trace.matches = {}
    trace.remove_noise()
    apis_set = trace.get_apis()
    encoded_trace = encode_trace(trace.trace)
    first_api = trace.first_api()
    if first_api != -1:
        match_models(encoded_trace, leaf_models, trace.matches, first_api)

def main_internal(trace):
    print(trace)
    tids = Trace.get_threads(trace)
    traces = {}
    for tid in tids:
        traces[tid] = Trace.gen(trace, tid)
        try:
            analysis(traces[tid])
            traces[tid].match_analysis()
            traces[tid].match_span_analysis()
        except Exception as exp:
            print("Trace: %s; Thread %d matching failed." % (trace, tid), exp)
    return (trace, traces)

def is_cached(trace):
    cache_file = "match_assestment/" + trace.split('/')[-1] + ".pickle"
    return os.path.isfile(cache_file)

#@persist("match_assestment", (0, ))
def main(trace):
    cache_file = "match_assestment/" + trace.split('/')[-1] + ".pickle"
    if is_cached(trace):
        cache = open(cache_file, "rb")
        ret = pickle.load(cache)[trace]
        print(trace + " already in cache")
        cache.close()
    else:
        ret = main_internal(trace)
        cache = open(cache_file, "wb")
        pickle.dump({trace: ret}, cache)
        cache.close()
    return ret

def avg_coveage(traces):
    covs = reduce(iconcat, [[x._match_span_results for x in thread.values() if x._match_span_results is not None] for thread in traces.values()], [])
    return sum(covs)/len(covs)

def avg_correct_match(traces):
    ms = reduce(lambda x,y: (x[0]+y[0], x[1]+y[1]),
                reduce(iconcat,
                       [[x._match_results for x in thread.values()
                         if x._match_results is not None]
                        for thread in traces.values()],
                       []),
                (0, 0))
    return ms[0]/(ms[0] + ms[1])

def avg_match_lenght(traces):
    tmp = reduce(iconcat,
                 [reduce(iconcat, [[x[1]-x[0] for x in t.matches]
                                   for t in app.values()],
                         list()) for app in traces.values()],
                 [])
    return sum(tmp)/len(tmp)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: %s [parallel] <trace>" % sys.argv[0], file=sys.stderr)
        sys.exit(1)

    parallel = False
    if sys.argv[1] == "parallel":
        parallel = True
        del sys.argv[1]

    models = load_models("models2.pickle")
    apis, syscalls = load_symbols()
    symbols_generator(apis | syscalls.keys());
    leaf_models = find_leaves_models(models, syscalls)
    if any(x == None for x in (models, apis, syscalls)):
        sys.exit(1)

    if parallel:
        args = [(x, ) for x in sys.argv[1:]]
        '''
        maxtasksperchild must be None otherwise the new child won't
        have thread identity Main and interruptingcow will stop working
        '''
        pool = Pool(10, maxtasksperchild=None)
        results = pool.starmap(main, args, chunksize=10)
        pool.close()
        pool.join()
        results = dict([x for x in results if x is not None])
        print("Parallel execution done. %d traces analyzed" % len(results))
    else:
        results = dict(map(lambda x: main(x), sys.argv[1:]))
