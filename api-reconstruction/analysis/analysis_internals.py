import IPython
import pickle
import numpy as np
import matplotlib.pyplot as plt
import re
import stat
import os
import sys
import random

from functools import reduce
from pathlib import Path

import nwalign as nw
from interruptingcow import timeout

from .classes import *
from .decorators import *
from .utils import *

## Declaring global objects
signal_regex = re.compile(r"--- SIG.* ---")
return_regex = re.compile(r"rt_sigreturn")

noisy_syscalls = ('futex', 'madvise', 'clock_gettime', 'sched_yield')

def all_symbols_for_api(kb, api):
    ret = set()
    for trace in kb[api]:
        trace = prune_syscalls_args(trace)
        for t, call in trace:
            ret.add(call)
    return ret

def traverse(d, api, visited=None):
    if api in traverse.cache:
        return traverse.cache[api]

    if visited is None:
        visited = set()

    # Avoid infinite recursion. Fallback to False, this should be safe
    if api in visited:
        return False

    visited |= set([api])
    if api not in d:
        traverse.cache[api] = False
        return False

    realizations = d[api]
    ret = False

    for r in realizations:
        sys = get_syscall_list_from_trace(r)
        if len(sys) != 0:
            visited -= set([api])
            traverse.cache[api] = True
            return True

    subapis = set()
    for r in realizations:
        subapis |= set(get_api_list_from_trace(r))

    for subapi in subapis:
        if traverse(d, subapi, visited):
            visited -= set([api])
            traverse.cache[api] = True
            return True

    visited -= set([api])
    traverse.cache[api] = False
    return False

def childs_are_weak_polymorph(d, api, visited=None):
    if api in childs_are_weak_polymorph.cache:
        return childs_are_weak_polymorph.cache[api]

    if visited is None:
        visited = set()

    # Avoid infinite recursion. Fallback to False, this should be safe
    if api in visited:
        return False

    visited |= set([api])
    if api not in d:
        childs_are_weak_polymorph.cache[api] = False
        return False

    realizations = d[api]
    ret = False

    subapis = set()
    for r in realizations:
        subapis |= set(get_api_list_from_trace(r))

    for subapi in subapis:
        if is_polymorphic(d, subapi):
            visited -= set([api])
            childs_are_weak_polymorph.cache[api] = True
            return True
        if is_leaf(d, subapi):
            continue
        if childs_are_weak_polymorph(d, subapi, visited):
            visited -= set([api])
            childs_are_weak_polymorph.cache[api] = True
            return True

    visited -= set([api])
    childs_are_weak_polymorph.cache[api] = False
    return False

def is_weak_polymorph(d, api):
    if is_polymorphic(d, api):
        return True
    if is_leaf(d, api):
        return False
    return childs_are_weak_polymorph(d, api)

def is_leaf(d, api):
    realizations = d[api]
    ret = True
    for r in realizations:
        for call in r:
            if call[0] == 'API':
                ret = False
                break
        if not ret:
            break
    return ret

def find_leaves(d):
    ret = set()
    for api in d:        
        if is_leaf(d, api):
            ret.add(api)
    return ret

def realizations_are_equals(r1, r2):
    r1 = prune_syscalls_args(r1)
    r2 = prune_syscalls_args(r2)
    if len(r1) != len(r2):
        return False

    for i in range(len(r1)):
        if r1[i] != r2[i]:
            return False
    return True

def is_polymorphic(d, api):
    realizations = d[api]
    for i in range(len(realizations) - 1):
        if not realizations_are_equals(realizations[i], realizations[i+1]):
            return True
    return False

def realization_is_empty(r):
    return len(r) == 0

def is_empty(d, api):
    realizations = d[api]
    for r in realizations:
        if not realization_is_empty(r):
            return False
    return True

def realization_makes_syscalls(r):
    for call in r:
        if call[0] == "SYS":
            return True
    return False

def makes_syscalls(d, api):
    realizations = d[api]
    for r in realizations:
        if realization_makes_syscalls(r):
            return True
    return False

def has_indirect_sys(d, api):
    return traverse(d, api)

def find_polymorph(d):
    ret = set()
    for api in d:
        if is_polymorphic(d, api):
            ret.add(api)
    return ret

def find_weak_polymorph(d):
    ret = set()
    childs_are_weak_polymorph.cache = {}
    for api in d:
        if is_weak_polymorph(d, api):
            ret.add(api)
    return ret

def find_empties(d):
    ret = set()
    for api in d:
        if is_empty(d, api):
            ret.add(api)
    return ret

def find_no_syscall_apis(d):
    ret = set()
    for api in d:
        if not makes_syscalls(d, api):
            ret.add(api)
    return ret

def find_no_indirect_sys(d):
    ret = set()
    traverse.cache = {}
    for api in d:
        if not has_indirect_sys(d, api):
            ret.add(api)
    return ret


def measures(leaves, polymorph, no_sys, no_ind_sys,
              no_leaves, monomorph, sys, ind_sys):
    print("0Sys/0API/Polymorph: " + str(len(no_sys & leaves & polymorph)))
    print("0Sys/0API/No-Polymorph: " + str(len(no_sys & leaves & monomorph)))
    print("1+Sys/0API/Polymorph: " + str(len(sys & leaves & polymorph)))
    print("1+Sys/0API/No-Polymorph: " + str(len(sys & leaves & monomorph)))

    print("0Sys/1+API/Polymorph: " + str(len(no_sys & no_leaves & polymorph)))
    print("0Sys/1+API/No-Polymorph: " +
          str(len(no_sys & no_leaves & monomorph)))
    print("1+Sys/1+API/Polymorph: " + str(len(sys & no_leaves & polymorph)))
    print("1+Sys/1+API/No-Polymorph: " + str(len(sys & no_leaves & monomorph)))


    print("0Ind_Sys/0API/Polymorph: " +
          str(len(no_ind_sys & leaves & polymorph)))
    print("0Ind_Sys/0API/No-Polymorph: " +
          str(len(no_ind_sys & leaves & monomorph)))
    print("1+Ind_Sys/0API/Polymorph: " +
          str(len(ind_sys & leaves & polymorph)))
    print("1+Ind_Sys/0API/No-Polymorph: " +
          str(len(ind_sys & leaves & monomorph)))

    print("0Ind_Sys/1+API/Polymorph: " +
          str(len(no_ind_sys & no_leaves & polymorph)))
    print("0Ind_Sys/1+API/No-Polymorph: " +
          str(len(no_ind_sys & no_leaves & monomorph)))
    print("1+Ind_Sys/1+API/Polymorph: " +
          str(len(ind_sys & no_leaves & polymorph)))
    print("1+Ind_Sys/1+API/No-Polymorph: " +
          str(len(ind_sys & no_leaves & monomorph)))


    print("0Sys/1+IndSys/Polymorph: " +
          str(len(no_sys & ind_sys & polymorph)))
    print("0Sys/1+IndSys/No-Polymorph: " +
          str(len(no_sys & ind_sys & monomorph)))

def build_precise_model_for_api(d, api, strong_monomorph):
    if api in build_precise_model_for_api.cache:
        return build_precise_model_for_api.cache[api]

    model = []
    realization = d[api][0]
    for call in realization:
        if call[0] == 'SYS':
            if (get_syscall_name(call[1]) not in ("futex", "madvise")
                and not call[1].startswith("--- SIGCHLD")):
                model.append(call)
            continue
        assert call[1] in strong_monomorph, (
            "%s supposed to be strong monomorph, but it's not" % call[1])
        model += build_precise_model_for_api(d, call[1], strong_monomorph)
    build_precise_model_for_api.cache[api] = model
    return model

def build_precise_models(d, strong_monomorph):
    build_precise_model_for_api.cache = {}
    models = {}
    for api in strong_monomorph:
        models[api] = build_precise_model_for_api(d, api, strong_monomorph)
    return models

def prune_malloc_syscalls(trace, entry_offset=0):
    if not hasattr(prune_malloc_syscalls, "mmap_regex"):
        mmap_regex = re.compile(r"mmap2?\(.*PROT_READ\|PROT_WRITE," +
                                r" MAP_PRIVATE\|MAP_ANONYMOUS\|MAP_NORESERVE," +
                                r" -1, 0.*= (0x[a-f\d]+)")
        prune_malloc_syscalls.mmap_regex = mmap_regex
        prctl_regex = re.compile(r"prctl\(PR_SET_VMA," +
                                 r" PR_SET_VMA_ANON_NAME, (0x[a-f\d]+).*" +
                                 r"\"libc_malloc\".*")
        prune_malloc_syscalls.prctl_regex = prctl_regex
        munmap_regex = re.compile(r"munmap\((0x[a-f\d]+),.*\)")
        prune_malloc_syscalls.munmap_regex = munmap_regex

    ret = []
    skip = 0
    l = len(trace) - 1
    for i, call in enumerate(trace):
        if skip != 0:
            skip -= 1
            continue
        if call[0+entry_offset] == "API":
            ret.append(call)
            continue
        m1 = prune_malloc_syscalls.mmap_regex.match(call[1+entry_offset])
        if i < l and m1:
            m2 = prune_malloc_syscalls.prctl_regex.match(trace[i+1][1+entry_offset])
            if m2 and m2.groups()[0] == m1.groups()[0]:
                skip = 1
                if i < l-1:
                    m3 = prune_malloc_syscalls.munmap_regex.match(
                        trace[i+2][1+entry_offset])
                    if m3 and m1.groups()[0] == m3.groups()[0]:
                        skip += 1
                        if i < l - 2 and 'munmap' in trace[i+3][1+entry_offset]:
                            skip += 1
                continue
        ret.append(call)
    return ret

## Recursively try to build precise model for an API and its sub-API
def try_build_precise_model_for_api(d, api, models, visited=None):
    if api in try_build_precise_model_for_api.cache:
        return try_build_precise_model_for_api.cache[api]

    if visited is None:
        visited = set()

    # Avoid infinite recursion. Fallback to False, this should be safe
    if api in visited:
        raise Exception()

    visited.add(api)

    if api in models:
        try_build_precise_model_for_api.cache[api] = models[api]
        visited -= set([api])
        return models[api]

    possible_models = []
    for realization in d[api]:
        try:
            pm = []
            for call in realization:
                if call[0] == 'SYS':
                    if (get_syscall_name(call[1]) not in ("futex", "madvise")
                        and not call[1].startswith('--- SIGCHLD')):
                        pm.append(call)
                        continue
                if call[1] in models:
                    pm += models[call[1]]
                    continue
                ## Try to build the model for the sub-API
                subapi_model = try_build_precise_model_for_api(d, call[1],
                                                           models, visited)
                if subapi_model is not None:
                    pm += subapi_model
                else:
                    visited -= set([api])
                    try_build_precise_model_for_api.cache[api] = None
                    return None
        except Exception:
            continue
        possible_models.append(pm)

    ret = None
    if len(possible_models) == 0:
        return ret
    for i in range(len(possible_models) - 1):
        if not realizations_are_equals(possible_models[i],
                                       possible_models[i+1]):
            break
    else:
        ret = possible_models[0]

    visited -= set([api])
    try_build_precise_model_for_api.cache[api] = ret
    return ret

def find_implicit_monomorph_models(d, models):
    ret = dict(models)
    try_build_precise_model_for_api.cache = {}
    for api in d:
        m = try_build_precise_model_for_api(d, api, models)
        if m is not None:
            ret[api] = m
    return ret

def check_0sys(no_sys, no_ind_sys):
    assert set(no_ind_sys) <= set(no_sys)

def check_polymorph(weak_polymorph, polymorph):
    assert weak_polymorph >= polymorph

def check_empties_have_precise_model(empties, precise_models):
    assert empties <= set(precise_models.keys())

def check_implicit_precise_models(implicit_precise_models, precise_models):
    assert set(precise_models.keys()) <= set(implicit_precise_models.keys())

def check_empties_have_empty_model(empties, empty_models):
    assert empties <= empty_models


def api_syscall_in_regex(reg):
    ret = set()
    for call in reg:
        ret.add(call[0])
    return ret

def symbols_generator(dictionary=None, start=0):
    if hasattr(symbols_generator, "_symbols"):
        return symbols_generator._symbols
    assert dictionary is not None, "Needs a dict to generate the symbols"
    symbols_set = set(dictionary)
    indexes = [x for x in range(start, start+len(symbols_set))]
    symbols = []
    symbols.append({chr(i): x
                   for i, x in zip(indexes, symbols_set)})

    forbidden = [c for c in list('$()*+-.?[\\]^|')]
    for c in forbidden:
        if c in symbols[0].keys():
            symb = symbols[0][c]
            symbols[0][c] = c
            new_symb = chr(indexes[-1] + 1)
            symbols[0][new_symb] = symb
            indexes.append(indexes[-1] + 1)
        else:
            symbols[0][c] = c

    symbols.append({y: x for x, y in symbols[0].items()})
    ret = (symbols[0], symbols[1])
    setattr(symbols_generator, "_symbols", ret)
    return ret


def encode_regex(regex, symbols=None):
    if symbols is None:
        symbols = symbols_generator()[1]
    ret = []
    for entry in regex:
        new_set = None
        if type(entry[0]) == str:
            new_set = set()
            new_set.add(symbols[entry[0]])
        else:
            new_set = {symbols[x] for x in entry[0]}
        ret.append((new_set, entry[1]))
    return ret


def encode_regex_str(regex, symbols=None):
    if symbols is None:
        symbols = symbols_generator()[1]
    ret = u"^"
    for entry in regex:
        if type(entry[0]) == str:
            ret += symbols[entry[0]]
        else:
            ret += u'(' + u'|'.join([symbols[x] for x in entry[0]]) + u')'

        if entry[1] == RegexFlags.OPTIONAL:
            ret += u'?'
        elif entry[1] == RegexFlags.MULTIPLE:
            ret += u'+'
        elif entry[1] == RegexFlags.OPTIONAL | RegexFlags.MULTIPLE:
            ret += u'*'
    ret += u'$'
    return ret


def encode_trace(trace, symbols=None):
    if symbols is None:
        symbols = symbols_generator()[1]
    trace = prune_syscalls_args(trace)
    ret = u""
    for call in trace:
        if call[1] in symbols:
            ret += symbols[call[1]]
    return ret


def decode_sequence(seq, symbols=None):
    if symbols is None:
        symbols = symbols_generator()[0]
    trace = []
    for c in seq:
        trace.append(symbols[c])
    return trace


def decode_regex(reg, symbols):
    ret = []
    for sys, cond in reg:
        if len(sys) == 1:
            ret.append((symbols[sys.pop()], cond))
        else:
            ret.append(({symbols[x] for x in sys}, cond))
    return ret

def decode_regex_str(reg, symbols=None):
    if symbols is None:
        symbols = symbols_generator()[0]
    l = list(reg)
    ret = RegexSequence()
    sequences = []
    cnt = 0
    i = -1
    ## Skip the initial ^ character, if any
    if l[0] == '^':
        i += 1

    i_max = len(l)
    ## Do not consider the final $ character, if any
    if l[i_max-1] == '$':
        i_max -= 1

    while i < i_max-1:
        i += 1
        entry = ...
        curr = l[i]
        if curr == u'(': ## Begin of a sequence or an alternative
            if cnt == 0:
                sequences.append(u'')
            else:
                tmp = sequences.pop()
                tmp += curr
                sequences.append(tmp)
            cnt += 1
            continue
        elif curr == u')': ## End of a sequence or an alternative
            cnt -= 1
            if cnt != 0:
                tmp = sequences.pop()
                tmp += curr
                sequences.append(tmp)
                continue

            inside = sequences.pop()
            alternatives = inside.split('|')
            if len(alternatives) > 1:
                alt_obj = RegexAlternative()
                for alt in alternatives:
                    if len(alt) == 1:
                       alt_obj.add(RegexSimple(symbols[alt]))
                    elif len(alt) == 2 and alt[1] in '+?*':
                        alt_obj.add(RegexSimple(symbols[alt[0]],
                                                RegexFlags.from_regex_modifier(alt[1])))
                    else:
                        ## Got a new sequence here!
                        alt_obj.add(decode_regex_str(alt, symbols))
                if i < i_max-1 and l[i+1] in '+?*':
                    ret.add(alt_obj, RegexFlags.from_regex_modifier(l[i+1]))
                    i += 1
                else:
                    ret.add(alt_obj)
            else:
                new_seq = decode_regex_str(inside, symbols)
                if i < i_max-1 and l[i+1] in '*?+':
                    new_seq.flag = RegexFlags.from_regex_modifier(l[i+1])
                    i += 1
                ret.add(new_seq)
            continue

        ## If we have already spot at least a '('
        if len(sequences) != 0:
            tmp = sequences.pop()
            tmp += curr
            sequences.append(tmp)
            continue

        ## Current entry is just a symbol
        entry = symbols[curr]
        if i < i_max-1 and l[i+1] in '?+*':
            entry_obj = RegexSimple(entry,
                                    RegexFlags.from_regex_modifier(l[i+1]))
            i += 1
        else:
            entry_obj = RegexSimple(entry)
        ret.add(entry_obj)

    if len(ret.expr) == 1 and type(ret.expr[0]) == RegexSequence:
        ret = ret.expr[0]
    return ret

def align_traces(trace1, trace2):
    symbols = symbols_generator()

    seq1 = encode_trace(trace1, symbols[1])
    seq2 = encode_trace(trace2, symbols[1])

    aligned = nw.global_align(seq1, seq2)

    decoded1 = decode_sequence(aligned[0], symbols[0])
    decoded2 = decode_sequence(aligned[1], symbols[0])
    return (decoded1, decoded2)


def align_regex_trace(regex, trace):
    symbols = symbols_generator()

    seq1 = encode_regex(regex, symbols[1])
    seq2 = encode_trace(trace, symbols[1])

    aligned = nw.global_align_regex(seq1, seq2)

    decoded1 = decode_regex(aligned[0], symbols[0])
    decoded2 = decode_sequence(aligned[1], symbols[0])
    return (decoded1, decoded2)


def sequence_match(regex, seq):
    r = encode_regex_str(regex)
    reg = re.compile(r)
    seq = encode_trace(seq)
    return reg.match(seq) is not None


def gen_regex(seq1, seq2):
    ret = []
    assert len(seq1) == len(seq2), "Sequences of different lenght"
    for i in range(len(seq1)):
        if seq1[i] == seq2[i]:
            ret.append((seq1[i], RegexFlags.MANDATORY))
        elif seq1[i] == "-":
            ret.append((seq2[i], RegexFlags.OPTIONAL))
        elif seq2[i] == "-":
            ret.append((seq1[i], RegexFlags.OPTIONAL))
        elif seq1[i] != seq2[i]:
            ret.append((set([seq1[i], seq2[i]]), RegexFlags.MANDATORY))
        else:
            assert False, "This should never happen"
    return ret


def update_regex(reg, seq):
    ret = []
    assert len(reg) == len(seq), "Sequences of different lenght"
    for i in range(len(reg)):
        if seq[i] in reg[i][0]:
            ret.append(reg[i])
        elif seq[i] == u"-":
            ret.append((reg[i][0], RegexFlags.OPTIONAL | reg[i][1]))
        elif reg[i][0] == u"-":
            ret.append((seq[i], RegexFlags.OPTIONAL | reg[i][1]))
        elif seq[i] not in reg[i][0]:
            to_add = set()
            if type(reg[i][0]) == str:
                to_add.add(reg[i][0])
            else:
                to_add |= reg[i][0]
            to_add.add(seq[i])
            ret.append((to_add, reg[i][1]))
        else:
            assert False, "This should never happen"
    return ret

def make_regex_conditional(regex):
    return [(entry[0], entry[1] | RegexFlags.OPTIONAL) for entry in regex]

def total_trace_length(traces):
    return sum([len(x) for x in traces])

def avg_trace_length(traces):
    return total_trace_length(traces)/len(traces)

@timeout(5)
def check_trace_matches(regex, trace):
    return regex.match_trace(trace, symbols_generator())

def check_traces_match(regex, traces, msg=''):
    sys.stdout.flush()
    success = 0
    tout = 0
    fails = 0
    print(msg, end='')
    for trace in traces:
        print('.', end='')
        try:
            if check_trace_matches(regex, trace):
                success += 1
            else:
                fails += 1
        except RuntimeError:
            tout += 1
    print('')
    return (success, tout, fails)


def regex_from_trace(trace):
    ret = RegexSequence()
    for x in trace:
        if x[0] == 'SYS':
            add = get_syscall_name(x[1])
        else:
            add = x[1]
        ret.add(add)
    return ret

def regex_for_api(kb, api):
    traces = [t for t in kb[api] if len(t) != 0]

    if len(traces) == 1:
        return (regex_from_trace(traces[0]), 0, 0, 0)

    if len(traces) == 0:
        return None

    if len(traces) > 10:
        train_len = min([50, int(len(traces)/2)])
    else:
        train_len = len(traces)

    test = traces[train_len:]
    traces = traces[0:train_len]

    first_alignement = align_traces(*traces[0:2])
    regex = gen_regex(*first_alignement)
    for trace in traces[2:]:
        align = align_regex_trace(regex, trace)
        regex = update_regex(*align)

    reg_obj = RegexSequence.from_list(regex)
    (success, tout, fails) = check_traces_match(reg_obj, traces,
                                                '%s TRAIN' % api)
    print(("### TRAIN Api: %s. %d traces. Matches/Timeouts/Fails %d/%d/%d" +
          " test traces") % (api, len(kb[api]), success, tout, fails))
    assert fails == 0, ("Regex for api %s failed to cover all" +
                        " the traces in the training set")

    (success, tout, fails) = check_traces_match(reg_obj, test,
                                                '%s TEST' % api)
    print(("### TEST Api: %s. %d traces. Matches/Timeouts/Fails %d/%d/%d" +
          " test traces\n") % (api, len(kb[api]), success, tout, fails))
    return (reg_obj, success, tout, fails)

def regexes_for_kb(kb, syscalls, regexes=None):
    symbols_generator({**kb, **syscalls})

    if regexes is None:
        regexes = {}
    for api, traces in kb.items():
        print(api)
        if avg_trace_length(traces) > 100:
            print("%s traces too big. Skipping" % api)
            regexes[api] = ...
            continue
        if api not in regexes or regexes[api] is None:
            regexes[api] = regex_for_api(kb, api)
            if len(regexes) % 100 == 0:
                dump_to_file(regexes, 'regex.pickle')
    dump_to_file(regexes, 'regex.pickle')
    return regexes

def test_regex(kb, api, regex):
    traces = [x for x in kb[api] if len(x) != 0]
    return check_traces_match(regex, traces)


def models_for_kb(kb, syscalls, models=None, debug=False):
    return APIGenericModel.generate_models(kb, syscalls, models, debug)

def models_less_generic(kb, syscalls, models=None, debug=False):
    return APILessGenericModel.generate_models(kb, syscalls, models, debug)

regex_find_conditional = re.compile(r'((.\?)+)')
def shrink_regex_repetitions(m):
    symbol = m.groups()[0]
    full_match = m.group()
    match_conditionals = regex_find_conditional.search(full_match)
    if not match_conditionals:
        conditional = False
    else:
        conditional = match_conditionals.group() == full_match
    return symbol + ('*' if conditional else '+')

regex_find_repetitions = re.compile(r'(.)\??(\1\??)+')
def regex_handle_single_call_repetitions(regex):
    reg_str = encode_regex_str(regex)
    new_reg = regex_find_repetitions.sub(shrink_regex_repetitions, reg_str)
    return decode_regex_str(new_reg)

def shrink_repetitions(m):
    symbol = m.groups()[0]
    full_match = m.group()
    if len(symbol) > 1 :
        symbol = '(' + symbol + ')'
    return symbol + '+'

find_repetitions = re.compile(r'(.+?)(\1)+')
def handle_call_repetitions(seq, original=None):
    if original is None:
        original = seq
    if type(seq) == list:
        trace = seq
        enc = encode_trace(trace)
        new_reg = find_repetitions.sub(shrink_repetitions, enc)
    elif (isinstance(seq, RegexSequence) or
          issubclass(type(seq), RegexSequence)):
        reg = seq
        enc = reg.to_string_regex(symbols_generator())
        new_reg = find_repetitions.sub(shrink_repetitions, enc)
    else:
        print(type(seq))
        assert False, seq

    if enc == new_reg:
        if enc == encode_trace(original):
            try:
                return decode_regex_str(encode_trace(original))
            except:
                return None
        return None
    try:
        if not re.compile(new_reg).match(encode_trace(original)):
            raise re.error('')
    except re.error:
        return None

    try:
        new_reg_obj = decode_regex_str(new_reg)
    except:
        return None
    match = new_reg_obj.match_trace(original, symbols_generator(), full=True)
    if not match:
        return None
    else:
        res = handle_call_repetitions(new_reg_obj, original)
        if res:
            return res
        else:
            return new_reg_obj


def measures_regexes(regexes):
    total_fails = 0
    total_timeout = 0
    total_success = 0
    too_long = set()
    too_short = set()
    for api, r in regexes.items():
        if r is None:
            too_short.add(api)
            continue
        if r is ...:
            too_long.add(api)
            continue
        total_fails += r[2]
        total_timeout += r[1]
        total_success += r[0]
    total = total_fails + total_timeout + total_success
    fails_ratio = total_fails / total
    timeout_ratio = total_timeout / total
    success_ratio = total_success / total
    return success_ratio, timeout_ratio, fails_ratio

def measures_models(models):
    total_fails = 0
    total_success = 0
    too_short = set()
    total = 0
    for api, model in models.items():
        if model is None:
            too_short.add(api)
            continue
        total_fails += model.test_results[1]
        total_success += model.test_results[0]
    total = total_fails + total_success
    fails_ratio = total_fails / total
    success_ratio = total_success / total
    return success_ratio, fails_ratio


def troublesome_regexes(regexes, min=0.15, max=1):
    ret = set()
    for api, v in regexes.items():
        if v is ... or v is None:
            continue
        total = sum(v[1:])
        if total == 0:
            continue
        if min <= v[3]/total <= max:
            ret.add((api, v[3]/total, total))
    return sorted(list(ret), key=lambda x: -x[1])

def troublesome_models(models, min=0.15, max=1):
    ret = set()
    for api, model in models.items():
        if model is None:
            continue
        results = model.test_results
        if sum(results) == 0:
            continue
        fail_ratio = results[1]/sum(results)
        if min <= fail_ratio <= max:
            ret.add((api, fail_ratio, sum(results)))
    return sorted(list(ret), key=lambda x: -x[1])


def expensive_regexes(regexes, min=0.01, max=1):
    ret = set()
    for api, v in regexes.items():
        if v is ... or v is None:
            continue
        total = sum(v[1:])
        if total == 0:
            continue
        if min <= v[2]/total <= max:
            ret.add((api, v[2]/total, total))
    return sorted(list(ret), key=lambda x: -x[1])


def regexes_split_test_results(regexes_test):
    return ({**{api: regex[0] for (api, regex) in regexes_test.items()
               if regex is not ... and regex is not None},
            **{api: None for (api, regex) in regexes_test.items()
               if regex is None}},
            {**{api: tuple(regex[1:]) for (api, regex) in regexes_test.items()
               if regex is not ... and regex is not None},
            **{api: None for (api, regex) in regexes_test.items()
               if regex is None}}
    )


def prune_kb_from_empties(kb, empties):
    ret = {}
    for api, traces in kb.items():
        ret[api] = []
        for trace in traces:
            n_trace = []
            for call in trace:
                if call[1] not in empties:
                    n_trace.append(call)
            ret[api].append(n_trace)
    return ret

def prune_kb_from_signals(kb):
    ret = {}
    for api, traces in kb.items():
        ret[api] = []
        for trace in traces:
            new_trace = []
            for call in trace:
                if not signal_regex.match(call[1]):
                    new_trace.append(call)
            ret[api].append(new_trace)
    return ret

def shuffle_kb(kb):
    for api, traces in kb.items():
        random.shuffle(traces)


def apis_same_models(models):
    ret = set()
    i = 0
    apis = list(models.keys())
    while i < len(apis):
        if models[apis[i]] is None:
            i += 1
            continue
        j = i + 1
        while j < len(apis):
            if models[apis[j]] is None:
                j += 1
                continue
            if len(models[apis[i]] & models[apis[j]]) > 0:
                ret.add((apis[i], apis[j]))
                break
            j += 1
        i += 1
    return ret


def api_match_model(models, to_check):
    for api, model in models.items():
        if model is None:
            continue
        if len(model & to_check) > 0:
            print('api %s matches' % api)


def find_leaves_models(models, syscalls):
    leaves_apis = {}
    if type(syscalls) == dict:
        syscalls = set(syscalls.keys())

    for api, model in models.items():
        if model is None:
            continue
        r = model.leaf_models(syscalls, models)
        if len(r) > 0 :
            leaves_apis[api] = r

    return leaves_apis

def kb_remove_hanging_calls(kb):
    for api, traces in kb.items():
        for trace in traces:
            i = 0
            while i < len(trace):
                if trace[i][0] == 'API' and trace[i][1] not in kb:
                    print("Removing call to %s from API %s" % (trace[i][1], api))
                    del trace[i]
                else:
                    i += 1

def overlapping_traces(kb, api):
    traces = {tuple(get_syscall_name(y[1])
                    for y in get_syscall_list_from_trace(x))
              for x in kb[api]}
    ret = []
    for k, v in kb.items():
         if k == api:
             continue
         for t in v:
             if len(t) == 0:
                 continue
             if len(get_api_list_from_trace(t)) != 0:
                 continue
             t = tuple(get_syscall_name(y[1])
                       for y in get_syscall_list_from_trace(t))
             if t in traces:
                 ret.append((k, t))
    return ret


#### local rare models: models whose frequency within the realizations of a given API is lower than a threshold
@persist("local_rare_cache", (1,))
def local_rare_models(models, threshold=0.01):
    ret = {}
    gen = ((api, ms) for api, ms in models.items() if ms)
    for api, ms in gen:
        tot = ms._counters['TOTAL']
        ret[api] = []
        for m, cnt in ms._counters.items():
            if type(m) == str and m == 'TOTAL':
                continue
            if (cnt/tot) < threshold:
                ret[api].append(m)
        if len(ret[api]) == 0:
            del ret[api]
    return ret

def find_model_occurrence(models, find):
    ret = set()
    for api, ms in models.items():
        if ms is None:
            continue
        for m in ms:
            if m == find:
                ret.add(api)
                break
    return ret

## rare = {API: [model1, model2, ...], ...}

#### global rare models: models that are rare for each API in which they appear
@persist("global_rare_cache", (2,))
def global_rare_models(models, rare=None, threshold=0.01):
    if rare is None:
        rare = local_rare_models(models, threshold)

    tmp = reduce(lambda x, y: x+y, [x for x in rare.values()])
    rare_list = []
    for m in tmp:
        if m not in rare_list:
            rare_list.append(m)
    rare_occurrences = {m: find_model_occurrence(rare, m) for m in rare_list}
    all_occurrences = {m: find_model_occurrence(models, m) for m in rare_list}

    global_rare = {m: rare_occurrences[m] for m in rare_list
                   if all_occurrences[m] == rare_occurrences[m]}
    return global_rare
