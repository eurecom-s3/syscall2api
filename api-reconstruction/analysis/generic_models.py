from .classes import *

class APIGenericModel(RegexAlternative):
    def __init__(self, api, realizations, train_size=-1):
        super().__init__(set(), RegexFlags.MANDATORY)
        self._api = api

        if train_size == -1:
            train_size = min(50, math.ceil(len(realizations)/2))

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

    def add_model(self, trace):
        if len(trace) == 0:
            self._empty_allowed = True
            return None
        if self.check_trace(trace):
            return None
        from .analysis_internals import handle_call_repetitions
        new_model = handle_call_repetitions(trace)
        from .analysis_internals import symbols_generator
        symbols = symbols_generator()
        if new_model is None:
            print(trace)
            import IPython; IPython.embed()
        self.expr.add(new_model)
        return new_model


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

        if len(traces) == 0:
            return None

        allow_empty = len(traces) != len(kb[api])

        m = cls(api, traces)
        m._empty_allowed = allow_empty
        m.test()
        return m

    @classmethod
    def generate_models(cls, kb, syscalls, models=None):
        from .analysis_internals import symbols_generator
        if hasattr(symbols_generator, '_symbols'):
            del symbols_generator._symbols
        symbols_generator({**kb, **syscalls})

        if models is None:
            models = {}

        from .analysis_internals import dump_to_file
        for api, traces in kb.items():
            print(api)
            if api not in models or models[api] is None:
                models[api] = cls.model_for_api(kb, api)
                if len(models) % 100 == 0:
                    dump_to_file(models, 'models.pickle')
        dump_to_file(models, 'models.pickle')
        return models

