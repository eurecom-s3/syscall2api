#!/usr/local/bin/ipython3 -i

import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict
from matplotlib.ticker import MaxNLocator
from itertools import product
from analysis import *
from analysis.match_evaluation import *
from math import log

traces = None
scopes = {"", "method", "class", "package"}
nremoved_syscalls = 0
noise = False  ## Uncomment for noise reduction
# noise = True   ## Uncomment for skipping noise reduction

def load_encode_traces():
    global traces, nremoved_syscalls
    if traces is not None:
        return traces, nremoved_syscalls
    tmp1 = load_compact_traces()
    original_lens = [len(x) for x in tmp1]
    tmp = [remove_noise_internals(x) for x in tmp1] if not noise else tmp1
    lens = [len(x) for x in tmp]
    traces = [encode_trace(t) for t in tmp]
    nremoved_syscalls = sum((y - x) for x, y in zip(lens, original_lens))
    return traces, nremoved_syscalls

def check_syscalls_frequency(syscalls, leaf_models, length=1):
    matches = check_syscalls_fast(syscalls, leaf_models, length)
    tmp = {entry[0]: [x[1] for x in matches if x[0] == entry[0]]
           for entry in matches}
    traces, nremoved = load_encode_traces()
    ret = {}
    matched_syscalls = defaultdict(set)
    for sys in tmp.keys():
        cnt = 0
        sys_enc = encode_trace([("SYS", x) for x in sys])
        sys_re = re.compile(sys_enc)
        for t in traces:
            findings = list(sys_re.finditer(t))

            ## Hack da straccio di licenza. Guido perdonami
            matched_syscalls[id(t)] |= {f.span()[0] for f in findings}

            cnt += len(findings)
        ret[sys] = (tmp[sys], cnt)
    non_matched_syscalls = defaultdict(set)
    for k in matched_syscalls:
        l = [t for t in traces if id(t) == k][0]
        non_matched_syscalls[k] = (len(l) + 1 - length -
                                   len(matched_syscalls[id(l)]))
    import IPython; IPython.embed()
    nm = sum((x for x in non_matched_syscalls.values()), 0)
    return ret, nm + nremoved

def effective_ambiguity(matches):
    return {x: (len(y[0]), y[1], (len(y[0]) - 1) * y[1])
            for x, y in matches.items()}

def check_syscalls(syscalls, leaf_models, length=1):
    ret = []
    syscalls = [s for s, v in syscalls.items() if len(v) != 0]
    it = product(syscalls, length)
    for sysc in it:
        trace = [('SYS', x) for x in sysc]
        matches = match(trace, leaf_models, length)
        for m in matches:
            ret += [(sysc, m[0][0])]
    return ret

def check_syscalls_fast(syscalls, leaf_models, length=1):
    ret = set()
    syscalls = [s for s, v in syscalls.items() if len(v) != 0]
    matchable = {}
    for api, models in leaf_models.items():
        for model in models:
            for entry in model.matchable_combo(length):
                if entry not in matchable:
                    matchable[entry] = []
                matchable[entry].append(api)

    for key, value in matchable.items():
        dec = tuple(decode_sequence(key))
        if all(x in syscalls for x in dec):
            ret |= {(dec, x) for x in value}

    return ret

## data = {syscall: ([API1, API2, ...], freq), }
def hist(data, label='', show=False, save=None):
    tmp = {x: len(v[0]) for x, v in data.items()}

    y_axis = np.bincount(np.array(list(tmp.values())))
    x_axis = np.arange(0, len(y_axis))
    plt.clf()
    plt.bar(x_axis, y_axis, width=1.0)
    axs = plt.axes()
    axs.yaxis.grid(which='major')
    axs.yaxis.set_major_locator(MaxNLocator(integer=True))
    axs.xaxis.set_major_locator(MaxNLocator(integer=True))
    plt.title("Histogram for %s syscalls-long traces" % label)
    plt.axis([0, max(x_axis), 0, max(y_axis)])
    if show:
        plt.show()
    plt.savefig('hist%s.png' % label, format='png')

    return (x_axis, y_axis)


## data = {syscall: ([API1, API2, ...], freq), }
def cdf(data, label='', show=False):
    tmp = {x: len(v[0]) for x, v in data.items()}

    y_axis = np.cumsum(np.bincount(np.array(list(tmp.values()))))
    norm = 100/max(y_axis)
    y_axis_norm = np.array(y_axis, dtype='float64') * norm
    x_axis = np.arange(0, len(y_axis))
    plt.clf()
    plt.plot(x_axis, y_axis_norm)
    axs = plt.axes()
    axs.yaxis.grid(which='major')
    axs.xaxis.grid(which='major')
    axs.xaxis.grid(which='minor')
    axs.yaxis.set_major_locator(MaxNLocator(integer=True))
    axs.xaxis.set_major_locator(MaxNLocator(integer=True))
    plt.axis([0, max(x_axis), 0, max(y_axis_norm)])

    axs2 = axs.twinx()
    axs2.plot(x_axis, y_axis)
    axs2.yaxis.set_major_locator(MaxNLocator(integer=True))

    plt.title("CDF %s syscalls-long traces" % label)
    plt.axis([0, max(x_axis), 0, max(y_axis)])
    if show:
        plt.show()
    plt.savefig('cdf%s.png' % label, format='png')

    return (x_axis, y_axis, y_axis_norm)

## data = {syscall: ([API1, API2, ...], freq), }
def fullcdf(data, label='', nm=0, show=False):
    tmp = {x: (len(v[0]), v[1]) for x, v in data.items()}
    tmp['asdccc'] = (0, nm)
    ndata = defaultdict(int)
    for (amb, freq) in tmp.values():
        ndata[amb] += freq

    ndata = sorted(ndata.items())
    y_axis_tmp = [x[1] for x in ndata]
    y_axis = []
    for x in y_axis_tmp:
        if len(y_axis) == 0:
            y_axis.append(x)
        else:
            y_axis.append(y_axis[-1] + x)
    x_axis = [x[0] for x in ndata]
    norm = 100/max(y_axis)
    y_axis_norm = np.array(y_axis, dtype='float64') * norm
    plt.clf()
    plt.plot(x_axis, y_axis_norm)
    axs = plt.axes()
    axs.yaxis.grid(which='major')
    axs.xaxis.grid(which='major')
    axs.xaxis.grid(which='minor')
    axs.yaxis.set_major_locator(MaxNLocator(integer=True))
    axs.xaxis.set_major_locator(MaxNLocator(integer=True))
    plt.axis([0, max(x_axis), 0, max(y_axis_norm)])

    axs2 = axs.twinx()
    axs2.plot(x_axis, y_axis)
    axs2.yaxis.set_major_locator(MaxNLocator(integer=True))

    plt.title("CDF %s syscalls-long traces" % label)
    plt.axis([0, max(x_axis), 0, max(y_axis)])
    if show:
        plt.show()
    plt.savefig('fullcdf%s.png' % label, format='png')

    return (x_axis, y_axis, y_axis_norm)

# matches = {((SYS1, SYS2, ...): {API1, API2, ...}, ...}
def dump_matches(matches, fp):
    for k, v in sorted(matches.items(), key=lambda x: (-len(x[1]), x[0])):
        if len(v) < 2:
            continue
        lines = ["### " + ", ".join(k) + "\n##### seen %d times" % v[1]]
        lines += sorted(v[0])
        fp.write("\n".join(lines))
        fp.write("\n\n")

def dump_ambiguity_scores(amb, fp):
    for k, v in sorted(amb.items(), key=lambda x: (-x[1][2], x[0])):
        lines = ["### " + ", ".join(k),
                 "Effective ambiguity = %d" % v[2],
                 "Marginal ambiguity = %d" % (v[0]-1),
                 "Frequency = %d" % v[1]]
        fp.write("\n".join(lines))
        fp.write("\n\n")

def aggregate(matches, scope):
    if scope == "":
        return matches
    func = {"method": get_api_method_name,
            "class": get_api_class,
            "package": get_api_package}[scope]
    return {s: ({func(a) for a in apis}, f)
            for s, (apis, f) in matches.items()}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage %s <models basename>", file=sys.stderr)
        sys.exit(1)

    if len(sys.argv) == 3:
        scope = sys.argv[2]
        if scope not in scopes:
            print("WARN: %s is not a valid scope. Defaulting to full" % scope,
                  file=sys.stderr)
            scope = ""
        elif scope == "full":
            scope = ""
    else:
        scope = ""

    model = sys.argv[1]
    print("Loading")
    apis, syscalls = load_symbols()
    syscalls = {k: v for k, v in syscalls.items() if v and len(v) != 0}
    models = load_models(model + ".pickle")
    symbols_generator(apis | syscalls.keys())    
    leaf_models = find_leaves_models(models, syscalls)

    matches = {}
    h = {}
    c = {}
    full_cdfs = {}
    for x in range(1, 6):
        print("Finding matches for %d syscalls-long traces" % x)
        m, nm = check_syscalls_frequency(syscalls, leaf_models, x)
        m = aggregate(m, scope)
        matches[x] = m
        amb = effective_ambiguity(m)
        h[x] = hist(m, str(x) + ("_" + scope if len(scope) else ""))
        c[x] = cdf(m, str(x) + ("_" + scope if len(scope) else ""))
        full_cdfs[x] = fullcdf(m, str(x) + ("_" + scope if len(scope) else ""), nm)
        with open("matches_%s_%d" % (scope, x), "w") as fp:
            dump_matches(m, fp)

        with open("scores_%s_%d" % (scope, x), "w") as fp:
            dump_ambiguity_scores(amb, fp)

    with open(model + "_hist.pickle", "wb") as fh:
        pickle.dump(h, fh)
    with open(model + "_cdf.pickle", "wb") as fc:
        pickle.dump(c, fc)
    with open(model + "_fullcdf.pickle", "wb") as fc:
        pickle.dump(full_cdfs, fc)
