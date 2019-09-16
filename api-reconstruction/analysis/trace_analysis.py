from functools import lru_cache
from operator import iconcat

from .analysis_internals import *
from .classes import *
from .decorators import *
from .utils import load_trace as lt

class Trace(object):
    def __init__(self, path, thread, trace):
        self._path = path
        self._thread = thread
        self.trace = trace
        self._noisy = True
        self._has_apis = True
        self.matches = None
        self._first_api = None
        self.apis = None
        self._match_span_results = None
        self._match_results = None

    def __getstate__(self):
        d = dict(self.__dict__)
        del d['trace']
        del d['apis']
        del d['_noisy']
        del d['_has_apis']
        del d['_first_api']
        return d

    def __setstate__(self, d):
        thread = d['_thread']
        path = d['_path']
        # d['trace'] = self.load_trace(path)[thread]
        d['trace'] = []
        d['_noisy'] = True
        d['_has_apis'] = True
        d['apis'] = None
        d['_first_api'] = None
        if '_match_span_results' not in d:
            d['_match_span_results'] = None
        if '_match_results' not in d:
            d['_match_results'] = None
        self.__dict__ = dict(d)

    def reload(self):
        self.trace = load_trace(self._path)[self._thread]
        self.remove_noise()
        self.get_apis()

    @classmethod
    def gen(cls, path, thread):
        t = load_trace(path)[thread]
        return cls(path, thread, t)

    @staticmethod
    @lru_cache(maxsize=10)
    def load_trace(trace_file):
        return lt(trace_file)

    @staticmethod
    def get_threads(trace_file):
        return list(load_trace(trace_file).keys())

    def first_api(self):
        if not self._has_apis:
            return self._first_api
        for index, entry in enumerate(self.trace):
            if entry[0] == 'API':
                return index
        return -1

    def get_apis(self):
        if self.apis:
            return list(self.apis)
        if not self._has_apis:
            raise Exception("Apis already removed")
        trace = self.trace
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
                    if len(tmp[api]) == 0:
                        continue
                    start = tmp[api].pop()
                    end = index
                    ret.append((start, end, api))
        self.remove_api_calls()
        self.apis = list(filter(lambda x: x[0] != x[1], ret))
        return self.apis

    def remove_api_calls(self):
        if not self._has_apis:
            return
        self._first_api = self.first_api()
        self.trace[:] = filter(lambda x: x[0] != 'API', self.trace)
        self._has_apis = False

    @staticmethod
    def _stack_remove_api(stack, api):
        while True:
            if len(stack) == 0:
                return
            (n, entry) = stack.pop()
            if api == entry:
                break

    @staticmethod
    def _get_api_span_internals(apis):
        ret = []
        apis = sorted(apis, key=lambda x: (x[0], -x[1]))
        if len(apis) == 0:
            return ret
        ret.append((apis[0][0], apis[0][1]))
        for api in apis[1:]:
            # range already covered
            if ret[-1][0] <= api[0] < ret[-1][1]:
                assert api[1] <= ret[-1][1], "This shouldn't happen"
                continue
            # contigous ranges
            if ret[-1][1] == api[0]:
                ret[-1] = (ret[-1][0], api[1])
            else:
                ret.append((api[0], api[1]))
        return ret

    def get_api_span(self):
        return self._get_api_span_internals(self.apis)

    def remove_noise(self):
        trace = self.trace
        to_remove = []
        for i, entry in enumerate(trace):
            if (entry[0] == 'SYS' and
                    get_syscall_name(entry[1]) in noisy_syscalls):
                to_remove.append(i)

        _list_remove_indexes(trace, to_remove)
        pruned = prune_malloc_syscalls(trace)
        ## This is to do everything in place, though it's very ugly
        for i in range(len(trace)-1, 0, -1):
            del trace[i]
        trace += pruned

    @staticmethod
    def _api_filter_leaf_only(apis):
        ret = []
        for index, (s, e, api) in enumerate(apis):
            if index == 0:
                ret += [(s, e, api)]
            (ns, _, _) = apis[index-1]
            if not (s <= ns < e):
                ret += [(s, e, api)]
        return ret

    def match_analysis(self, leaf_only=True):
        if self._match_results:
            return self._match_results
        if not self.apis or not self.matches:
            return None

        apis = (self._api_filter_leaf_only(self.apis)
                if leaf_only else self.apis)
        nhit = 0
        nmiss = 0
        for (s, e, api) in apis:
            if (s, e) not in self.matches:
                nmiss += 1
                continue
            if api in self.matches[(s, e)]:
                nhit += 1
            else:
                nmiss += 1
        self._match_results = (nhit, nmiss)
        return self._match_results

    def match_span(self):
        matches = set(reduce(iconcat,
                             map(lambda x: [(x[0][0], x[0][1], y)
                                            for y in x[1]],
                                 self.matches.items()),
                             []))
        apis = set(self.apis)
        correct_matches = apis & matches
        return self._get_api_span_internals(correct_matches)

    def match_span_analysis(self):
        if self._match_span_results is not None:
            return self._match_span_results
        span_apis = sum(j-i for i,j in self.get_api_span())
        if span_apis == 0:
            return None
        span_matches = sum(j-i for i,j in self.match_span())
        self._match_span_results = span_matches/span_apis
        return self._match_span_results

    def average_match_lenght(self):
        if len(self.matches) != 0:
            return sum((j-i) for (i, j) in self.matches)/len(self.matches)

def _list_remove_indexes(l, i):
    for entry in i[::-1]:
        del l[entry]

def prune_signal_handlings(trace):
    signal_regex = re.compile(r"--- SIG([^ ]+) .* ---")
    return_regex = re.compile(r"rt_sigreturn")
    ret = []
    skip = False
    for call in trace:
        if not skip:
            if call[0] == "API":
                ret.append(call)
                continue
            match = signal_regex.match(call[1])
            try:
                if match and match.groups()[0] != "CHLD":
                    skip = True
                    continue
            except:
                import IPython; IPython.embed()
            ret.append(call)
        if skip:
            if call[0] == "API":
                IPython.embed()
            if return_regex.match(call[1]):
                skip = False
                continue
    return ret


def trace_trim_syscalls(trace):
    ret = []
    trace = prune_signal_handlings(prune_malloc_syscalls(trace))
    for entry in trace:
        if entry[0] == 'SYS':
            if get_syscall_name(entry[1]) in ('futex', 'madvise'):
                continue
        ret.append(entry)
    return ret
