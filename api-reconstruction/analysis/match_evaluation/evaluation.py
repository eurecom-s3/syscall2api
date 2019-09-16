from ..analysis_internals import *
import matplotlib.pyplot as plot, numpy as np

SEARCH = "SEARCH"
MATCH = "MATCH"
FULL_SEARCH = "FULL_SEARCH"

methods = {SEARCH: 'search_trace_encoded', MATCH: 'match_trace_encoded',
           FULL_SEARCH: 'findall_trace_encoded'}

def evaluate_match(trace, kb_models, stop=100):
    matches = _matches(trace, kb_models, stop, method=MATCH, full=True)
    return matches

def evaluate_search(trace, kb_models, stop=100):
    matches = _matches(trace, kb_models, stop, method=SEARCH, full=False)
    return matches

def evaluate_full_search(trace, kb_models, stop=100):
    matches = _matches(trace, kb_models, stop, method=FULL_SEARCH)
    ret = {}

    for index, l in matches.items():
        ret[index] = []
        for model, match in l:
            ret[index] += [(model, x) for x in match]
    return ret

def _matches(trace, kb_models, stop=100, method=MATCH, full=True):
    ret = {}
    for x in range(1, stop+1):
        encoded_trace = encode_trace(trace[:x])
        ret[x] = []
        for api, models in kb_models.items():
            for model in models:
                m = getattr(model, methods[method])(encoded_trace, full=full)
                if m:
                    ret[x].append(((api, model), m))
    return ret

def match(trace, kb_models, stop=100):
    ret = []
    encoded_trace = encode_trace(trace[:stop])
    for api, models in kb_models.items():
        for model in models:
            m = model.match_trace_encoded(encoded_trace, full=True)
            if m:
                ret.append(((api, model), m))
    return ret

def plot_evaluation(trace, kb_models, stop=100, funcs=None, names=None):
    if funcs is None:
        funcs = [evaluate_match, evaluate_search, evaluate_full_search]
        names = [MATCH, SEARCH, FULL_SEARCH]
    ret = {}
    for func, name in zip(funcs, names):
        ev = func(trace, kb_models, stop=stop).items()
        ret[name] = dict(ev)
        ev = ([x[0] for x in ev], [len(x[1]) for x in ev])
        x = np.array(ev[0])
        y = np.array(ev[1])
        plt.plot(x, y, label=name)
        plt.xticks(np.arange(min(x), max(x)+1, int((max(x)-min(x))/10)))
        plt.legend()
        plt.grid()
    plt.show()
    return ret

def hashable_match(match_obj):
    return (match_obj[0], match_obj[1].span())

def hashable_evaluations(res):
    return {i: {hashable_match(x) for x in v} for i, v in res.items()}

def validate_guess(trace, kb_models, stop=20):
    match_res = hashable_evaluations(evaluate_match(trace, kb_models, stop))
    search_res = hashable_evaluations(evaluate_search(trace, kb_models, stop))
    full_res = hashable_evaluations(evaluate_full_search(trace, kb_models,
                                                         stop))

    for key in match_res:
        assert match_res[key] <= search_res[key], (match_res[key],
                                                   search_res[key])
        assert search_res[key] <= full_res[key], (search_res[key] -
                                                  full_res[key])

## matches -> [((api, model), regex match obj), ...]
## expected -> [(start, end, api), ...]
## offset -> offset to be added to the starting point of the match object
def check_matches(matches, expected, offset=0):
    success = 0
    fails = 0
    cnt = 0
    for m in matches:
        entry = (m[1].start()+offset, m[1].end()+offset, m[0][0])
        if entry in expected:
            success += 1
        else:
            fails += 1
        cnt += 1
    return (success/cnt, fails/cnt)
