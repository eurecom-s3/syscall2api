from multiprocessing import Pool
from .classes import *
import itertools

class RegexGeneralizableSequence(RegexSequence):
    def __init__(self, expr=None, flag=RegexFlags.MANDATORY, api=None,
                 generalized=False, original_trace=None):
        super().__init__(expr, flag, api)
        self._generalized = generalized
        self._original_trace = original_trace

    @classmethod
    def from_RegexSequence(cls, reg, generalized=True, original_trace=None):
        ret = cls(reg.expr, reg.flag, reg.api, generalized, original_trace)
        return ret

    @classmethod
    def from_trace(cls, api, trace):
        ret = cls(api=api, original_trace=trace, generalized=False)
        for typ, call in trace:
            if typ == 'SYS':
                from .analysis_internals import get_syscall_name
                call = get_syscall_name(call)
            new_call = RegexSimple(call)
            ret.add(new_call)
        return ret

class APILessGenericModel(RegexAlternative):
    MAX_TRAIN_SIZE = 100
    def __init__(self, api, realizations, train_size=-1, ntraces=None):
        super().__init__(set(), RegexFlags.MANDATORY)
        self._api = api
        self._traces = realizations
        if ntraces is None:
            self._ntraces = len(self._traces)
        else:
            self._ntraces = ntraces

        if train_size == -1:
            train_size = min(APILessGenericModel.MAX_TRAIN_SIZE,
                             math.ceil(len(realizations)/2))

        self._train = []
        self._redundant = []

        i = 0
        j = 0
        while j < train_size and i < len(realizations):
            if self.add_model(realizations[i]):
                self._train.append(realizations[i])
                j += 1
            else:
                self._redundant.append(realizations[i])
            i += 1
        self._train_size = j
        self._test = realizations[i:]

        print("API %s -> %d train, %d redundant, %d test" %
              (api, self._train_size, len(self._redundant), len(self._test)))
        self._empty_allowed = False
        self.test_results = (0, 0)
        self._counters = None

    def add_model(self, trace):
        if len(trace) == 0:
            self._empty_allowed = True
            return None
        if self.check_trace(trace):
            return None

        new_model = RegexGeneralizableSequence.from_trace(self._api, trace)

        ## Check if the same model is already among the alternatives
        for old_model in self.expr:
            if new_model == old_model:
                return None

        ## Check if one of the alternatives, once repetitions are removed
        from .analysis_internals import handle_call_repetitions
        try:
            rep = handle_call_repetitions(trace)
        except RuntimeError:
            ## too expensive to shrink the model... Return None
            return None

        if rep is None:
            print(self._api, trace)
        generalized_new_model = RegexGeneralizableSequence.from_RegexSequence(
            rep, generalized=True,
            original_trace=trace)
        to_remove = set()
        for old_model in self.expr:
            if old_model._generalized and old_model == generalized_new_model:
                return None

            try:
                check = handle_call_repetitions(old_model._original_trace)
            except RuntimeError:
                ## timeout while shrinking this model. just skip
                continue

            if check == generalized_new_model:
                to_remove.add(old_model)

        ## All generalized models differ from the new one
        ## Add it as a non generic model
        if len(to_remove) == 0:
            self.expr.add(new_model)
            return new_model

        ## Remove those generalized models that matched
        ## Add the new generalized one
        self.expr -= to_remove
        self.expr.add(generalized_new_model)
        return generalized_new_model

    def check_trace(self, trace):
        for model in self.expr:
            try:
                if model.match_trace(trace, full=True):
                    return True
            except RuntimeError:
                print("API %s timedout" % self._api, flush=True)
        return False


    def test(self, test=None):
        if test is None:
            test = self._test
        successes = len(self._redundant)
        fails = 0
        for trace in test:
            if self.check_trace(trace):
                successes += 1
            else:
                fails += 1
        self.test_results = (successes, fails)
        return self.test_results

    def count_matches(self):
        if self._traces is None:
            raise Exception("count_matches can be used" +
                            " only if the original traces are available")
        self._counters = {k: 0 for k in self.expr}
        for model, trace in itertools.product(self.expr, self._traces):
            if model.match_trace(trace, full=True):
                self._counters[model] += 1
        self._counters['TOTAL'] = self._ntraces

    ## Avoid serialization of the training and test sets.
    ## It's just a waste of space/memory/time
    def __getstate__(self):
        d = dict(self.__dict__)
        del d['_traces']
        del d['_train']
        del d['_test']
        del d['_redundant']
        return d

    def __setstate__(self, d):
        d = dict(d)
        d['_traces'] = None
        d['_train'] = None
        d['_test'] = None
        d['_redundant'] = None
        self.__dict__ = d

    def __len__(self):
        return len(self.expr)

    def __iter__(self):
        return iter(self.expr)

    def __and__(self, other):
        if type(self) != type(other):
            return set()
        ret = set()
        for x1 in self.expr:
            for x2 in other.expr:
                if x1 == x2:
                    ret.add(x1)
        return ret

    def syscalls_only_models(self, syscalls):
        ret = []
        for model in self.expr:
            if model.is_syscalls_only(syscalls):
                ret.append(model)
        return ret

    def leaf_models(self, syscalls, models):
        ret = self.syscalls_only_models(syscalls)
        for model in self.expr:
            if model in ret:
                continue
            if model.is_leaf(models, syscalls):
                ret.append(model)
        return ret

    @classmethod
    def model_for_api(cls, kb, api, debug=False):
        if debug:
            from .analysis_internals import symbols_generator
            del symbols_generator._symbols
            symbols_generator(all_symbols_for_api(kb, api), start=65)

        traces = [t for t in kb[api] if len(t) != 0]
        ntraces = len(traces)

        if len(traces) == 0:
            return None

        allow_empty = len(traces) != len(kb[api])

        m = cls(api, traces, ntraces=ntraces)
        m._empty_allowed = allow_empty
        # m.test()
        # m.count_matches()
        return m

    @classmethod
    def model_for_api_parallel(cls, kb, api):
        print(api)
        ret = cls.model_for_api(kb, api)
        return (api, ret)

    @classmethod
    def generate_models(cls, kb, syscalls, models=None, parallel=False):
        from .analysis_internals import symbols_generator, dump_to_file
        if hasattr(symbols_generator, '_symbols'):
            del symbols_generator._symbols
        symbols_generator({**kb, **syscalls})

        if models is None:
            models = {}

        if not parallel:
            for api, traces in kb.items():
                print(api)
                if api not in models or models[api] is None:
                    models[api] = cls.model_for_api(kb, api)
                    if len(models) % 1000 == 0:
                        dump_to_file(models, 'models2.pickle')
        else:
            pool = Pool(8)
            args = (({api:kb[api]}, api) for api in kb.keys())
            models = dict(pool.starmap(cls.model_for_api_parallel,
                                       args, chunksize=100))
            pool.close()
            pool.join()
        dump_to_file(models, 'models2.pickle')
        return models

