import re
import math
from functools import lru_cache

from enum import Enum
from interruptingcow import timeout

class RegexFlags(Enum):
    MANDATORY = 0
    OPTIONAL  = 1
    MULTIPLE  = 2
    MULTIPLE_OPTIONAL = OPTIONAL | MULTIPLE
    def __or__(self, other):
        t = type(other)
        if t == RegexFlags:
            v = other.value
        else:
            v = other
        return RegexFlags(self.value | v)

    def regex_modifier(self):
        if self == self.MANDATORY:
            ret = u""
        elif self == self.OPTIONAL:
            ret = u"?"
        elif self == self.MULTIPLE:
            ret = u"+"
        elif self == self.MULTIPLE_OPTIONAL:
            ret = u"*"
        else:
            assert False, 'Unexpected value for RegexFlags'
        return ret

    @classmethod
    def from_regex_modifier(cls, mod):
        if mod == '?':
            return cls.OPTIONAL
        if mod == '+':
            return cls.MULTIPLE
        if mod == '*':
            return cls.MULTIPLE_OPTIONAL
        return cls.MANDATORY


class RegexElement():
    def __init__(self, expr, flag):
        self.expr = None
        self.flag = flag

    def to_string_regex(self, symbols):
        return u""

    def __str__(self):
        return self.expr.__str__() + ", " + self.flag.__str__()

    def __eq__(self, other):
        return type(self) == type(other) and self.flag == other.flag

    def __hash__(self):
        return id(self)

class RegexSimple(RegexElement):
    def __init__(self, expr, flag=RegexFlags.MANDATORY):
        self.expr = expr
        self.flag = flag

    def to_string_regex(self, symbols):
        ret = symbols[1][self.expr] + self.flag.regex_modifier()
        return ret

    def __str__(self):
        return self.expr + ", " + self.flag.__str__()

    def __eq__(self, other):
        if not super().__eq__(other):
            return False
        if self.expr == other.expr:
            return True
        return False

    def __hash__(self):
        return super().__hash__()

    def is_syscall(self, syscalls):
        return self.expr in syscalls

    def max_lenght(self):
        return 0 if self.flag == RegexFlags.MULTIPLE else 1

class RegexAlternative(RegexElement):
    def __init__(self, alternatives=frozenset(), flag=RegexFlags.MANDATORY):
        self.expr = set()
        for x in alternatives:
            self.add(x)
        self.flag = flag
        self.regex = None

    def add(self, expr):
        self.regex = None
        if type(expr) == str:
            new = RegexSimple(expr, RegexFlags.MANDATORY)
        else:
            new = expr
        self.expr.add(new)

    def to_string_regex(self, symbols):
        if self.regex:
            return self.regex
        ret = u"("
        for x in self.expr:
            assert isinstance(x, RegexElement), ("Found element %s not " +
                                                 "belonging to the " +
                                                 "RegexElement class in " +
                                                 "RegexAlternative") % x.__str__()
            ret += x.to_string_regex(symbols) + u"|"
        ret = ret[:-1] + u")" + self.flag.regex_modifier()
        self.regex = ret
        return self.regex

    def __str__(self):
        ret = '{\n  '
        tmp = ',\n'.join([x.__str__() for x in self.expr])
        ret += '\n  '.join(tmp.split("\n"))
        ret += '\n}'
        return ret

    def replace_api_calls(self, regexes, recursions=None):
        if self.replaced:
            return
        new_alt = set()

        for entry in self.expr:
            if type(entry) == RegexSimple:
                expr = entry.expr
                if expr in regexes:
                    if expr in recursions:
                        continue
                    recursions.append(expr)
                    regexes[expr].replace_api_calls()
                    recursions.pop()
                    new_alt.add(regexes[expr])
                else:
                    new_alt.add(entry)
            elif type(entry) == RegexSequence:
                entry.replace_api_calls(regexes, recursions)
                new_alt.add(entry)
            elif type(entry) == RegexAlternative:
                print('Happened')
                entry.replace_api_calls(regexes, recursions)
        self.expr = new_alt
        self.replaced = True
        return

    def __eq__(self, other):
        if not super().__eq__(other):
            return False
        for x1 in self.expr:
            for x2 in other.expr:
                if x1 == x2:
                    break
            else:
                return False
        return True

    def __hash__(self):
        return super().__hash__()

class RegexSequence(RegexElement):
    def __init__(self, expr=None, flag=RegexFlags.MANDATORY, api=None):
        if expr is None:
            expr = []
        self.expr = expr
        self.flag = flag
        self.regex = None
        self.compiled = None
        self.compiled_full = None
        self.api = api
        self.replaced = False

    def __getstate__(self):
        d = dict(self.__dict__)
        del d['compiled']
        del d['compiled_full']
        return d

    def __setstate__(self, d):
        d['compiled'] = None
        d['compiled_full'] = None
        self.__dict__ = dict(d)


    def add(self, expr, flag=RegexFlags.MANDATORY):
        if type(expr) == str:
            expr = RegexSimple(expr, flag)
        assert isinstance(expr, RegexElement), ("Found element not " +
                                                "belonging to the " +
                                                "RegexElement class in " +
                                                "RegexSequence")
        self.expr.append(expr)
        self.regex = None
        self.compiled = None
        self.compiled_full = None

    def to_string_regex(self, symbols, final=False, full=False):
        if full and self.compiled_full:
            return self.compiled_full.pattern
        if not full and self.compiled:
            return self.compiled.pattern

        ret = u""
        for x in self.expr:
            assert isinstance(x, RegexElement), ("Found element not " +
                                                 "belonging to the " +
                                                 "RegexElement class in " +
                                                 "RegexAlternative")
            ret += x.to_string_regex(symbols)
        if not final or self.flag != RegexFlags.MANDATORY:
            ret = u"(" + ret + u")" + self.flag.regex_modifier()
        if full:
            ret = u"^" + ret + u"$"

        self.regex = ret
        if full:
            self.compiled_full = re.compile(ret)
        else:
            self.compiled = re.compile(ret)
        return self.regex

    @timeout(5)
    def match_trace(self, trace, symbols=None, full=False):
        if symbols is None:
            from .analysis_internals import symbols_generator
            symbols = symbols_generator()
        from .analysis_internals import encode_trace
        encoded = encode_trace(trace, symbols[1])
        return self.match_trace_encoded(encoded, full, symbols)

    @timeout(5)
    def match_trace_encoded(self, encoded_trace, full=False, symbols=None):
        if symbols is None:
            from .analysis_internals import symbols_generator
            symbols = symbols_generator()
        if full:
            if not self.compiled_full:
                self.to_string_regex(symbols, final=True, full=full)
            return self.compiled_full.match(encoded_trace)
        else:
            if not self.compiled:
                self.to_string_regex(symbols, final=True, full=full)
            return self.compiled.match(encoded_trace)

    @timeout(5)
    def search_trace(self, trace, symbols=None, full=False):
        if symbols is None:
            from .analysis_internals import symbols_generator
            symbols = symbols_generator()
        from .analysis_internals import encode_trace
        encoded = encode_trace(trace, symbols[1])
        return self.search_trace_encoded(encoded, full, symbols)

    @timeout(5)
    def search_trace_encoded(self, encoded_trace, full=False, symbols=None):
        if symbols is None:
            from .analysis_internals import symbols_generator
            symbols = symbols_generator()
        if full:
            if not self.compiled_full:
                self.to_string_regex(symbols, final=False, full=full)
            return self.compiled_full.search(encoded_trace)
        else:
            if not self.compiled:
                self.to_string_regex(symbols, final=False, full=full)
            return self.compiled.search(encoded_trace)

    @timeout(5)
    def findall_trace(self, trace, symbols=None, full=None):
        if symbols is None:
            from .analysis_internals import symbols_generator
            symbols = symbols_generator()
        from .analysis_internals import encode_trace
        encoded = encode_trace(trace, symbols[1])
        return self.findall_trace_encoded(encoded, full, symbols)

    @timeout(5)
    def findall_trace_encoded(self, encoded_trace, symbols=None, full=None):
        if symbols is None:
            from .analysis_internals import symbols_generator
            symbols = symbols_generator()
        if not self.compiled:
            self.to_string_regex(symbols, final=False, full=False)
        return self.compiled.finditer(encoded_trace)

    @classmethod
    def from_list(cls, l):
        ret = cls()
        for entry,flag in l:
            if type(entry) == str:
                new = RegexSimple(entry, flag)
            elif type(entry) == set:
                new = RegexAlternative(entry, flag)
            else:
                assert False, "Not sure this can happen"
            ret.add(new, flag)
        return ret

    def __str__(self):
        ret = '[\n  '
        tmp = '\n'.join(x.__str__() for x in self.expr)
        ret += '\n  '.join(tmp.split('\n'))
        ret += '\n], ' + str(self.flag)
        return ret

    def replace_api_calls(self, regexes, recursions=None):
        if self.replaced:
            return
        if recursions is None:
            recursions = []
        if self.api and self.api in recursions:
            return
        if self.api is not None:
            recursions.append(self.api)

        new_seq = []
        for entry in self.expr:
            if type(entry) == RegexSimple:
                expr = entry.expr
                if expr in regexes.keys():
                    if expr in recursions:
                        continue
                    recursions.append(expr)
                    regexes[expr].replace_api_calls(regexes, recursions)
                    recursions.pop()
                    new_seq += regexes[expr].expr
                else:
                    new_seq.append(entry)
                continue
            if type(entry) == RegexSequence:
                entry.replace_api_calls(regexes, recursions)
                new_seq += entry.expr
                continue
            if type(entry) == RegexAlternative:
                pass
        self.expr = new_seq
        self.replaced = True
        return

    def contains_loops(self, regexes, original_api=None, recursions=None):
        if self.replaced:
            return False

        ret = False
        if recursions is None:
            recursions = []
        if original_api is None:
            original_api = self.api

        for entry in self.expr:
            if type(entry) == RegexSequence:
                loop = entry.contains_loops(regexes, original_api, recursions)
                if loop is not None:
                    return loop
            elif type(entry) == RegexSimple:
                expr = entry.expr
                if expr == self.api:
                    return [expr]

                if expr in recursions:
                    indx = recursions.index(expr)
                    return recursions[indx:] + [expr]

                if expr in regexes: ## it's an API, recurse
                    if expr not in recursions:
                        recursions.append(expr)
                    loop = regexes[expr].contains_loops(regexes, original_api,
                                                        recursions)
                    if loop is not None:
                        return loop
                    recursions.remove(expr)

            elif type(entry) == RegexAlternative:
                expr2 = entry.expr
                for x in expr2:
                    assert type(x) == RegexSimple, "Original %s, Current %s, RegexElement %s" %(original_api, self.api, entry)
                    expr = x.expr
                    if expr == self.api:
                        return [expr]
                    if expr in recursions:
                        indx = recursions.index(expr)
                        return recursions[indx:] + [expr]

                    if expr in regexes: ## it's an API, recurse
                        if expr not in recursions:
                            recursions.append(expr)
                        loop = regexes[expr].contains_loops(regexes,
                                                            original_api,
                                                            recursions)
                        if loop is not None:
                            return loop
                        recursions.remove(expr)
        return None

    def eq(self, other):
        from .analysis_internals import symbols_generator
        symbols = symbols_generator()
        return self.to_string_regex(symbols) == other.to_string_regex(symbols)
    def __eq__(self, other):
        return self.eq(other)
        if not super().__eq__(other):
            return False
        return self.expr == other.expr

    def __hash__(self):
        return super().__hash__()

    def is_syscalls_only(self, syscalls):
        for x in self.expr:
            if type(x) == RegexSimple:
                if not x.is_syscall(syscalls):
                    return False
            elif type(x) == RegexSequence:
                if not x.is_syscalls_only(syscalls):
                    return False
            else:
                assert False, "This should never happen"
        return True

    # Leaf: at least one syscalls and all the API calls allow empty models
    def is_leaf(self, models, syscalls):
        syscall = False
        for x in self.expr:
            if type(x) == RegexSimple:
                if x.expr in models and not models[x.expr]._empty_allowed:
                    return False
                elif x.expr in syscalls:
                    syscall = True
            elif type(x) == RegexSequence:
                if not x.is_leaf(models, syscalls):
                    return False
            else:
                assert False, "This should never happen"
        return syscall

    @staticmethod
    def _gen_combo(expr, ret, symbols, current='', length=1):
        if len(expr) == 0 and len(current) == length:
            ret.add(current)
            return

        if len(current) > length or len(expr) == 0:
            return

        if type(expr[0]) != RegexSimple:
            print("Not sure what to do!")
            return

        curr_chr = symbols[1][expr[0].expr]
        RegexSequence._gen_combo(expr[1:], ret, symbols,
                                 current+curr_chr, length)
        if expr[0].flag == RegexFlags.MULTIPLE:
            RegexSequence._gen_combo(expr, ret, symbols,
                                     current+curr_chr, length)

    def matchable_combo(self, length=1):
        from .analysis_internals import symbols_generator
        symbols = symbols_generator()

        if len(self.expr) > length:
            return list()
        ret = set()
        RegexSequence._gen_combo(self.expr, ret, symbols, length=length)
        return ret

    @classmethod
    def from_trace(cls, api, trace):
        ret = cls(api=api)
        for typ, call in trace:
            if typ == 'SYS':
                from .analysis_internals import get_syscall_name
                call = get_syscall_name(call)
            new_call = RegexSimple(call)
            ret.add(new_call)
        return ret

    def first_entry(self):
        if type(self.expr[0]) == RegexSimple:
            return self.expr[0].expr
        else:
            return self.expr[0].first_entry()

    @lru_cache(maxsize=None)
    def max_lenght(self):
        if self.flag == RegexFlags.MULTIPLE:
            return 0
        lenghts = [x.max_lenght() for x in self.expr]
        if any(x == 0 for x in lenghts):
            return 0
        return sum(lenghts)

from .generic_models import APIGenericModel as APIModel
