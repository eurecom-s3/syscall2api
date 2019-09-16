#!/usr/local/bin/ipython3 -i

import sys

from analysis import *
import analysis.classes as classes

import nwalign as nw

kb = {}
apis = {}
syscalls = {}
regexes = {}
models = {}
models2 = {}
kb_file = 'kb_no_empties.pickle'
regex_file = 'new_regex.pickle'
models_file = 'models.pickle'
models2_file = 'models2.pickle'
symbols_file = 'symbols.pickle'
leaf_models = {}

def first_run():
    global kb
    global apis
    global syscalls
    global regexes
    global models
    global symbols_file

    kb_file = "pruned_db.pickle"

    if not Path(kb_file).is_file():
        print("Error: No KB file found", file=sys.stderr)
        sys.exit(1)
    with open(kb_file, "rb") as pf:
        d = pickle.load(pf)
        syscalls = pickle.load(pf)

    d = prune_kb_from_signals(d)
    print("Finding leaf apis")
    leaves = find_leaves(d)
    print("Finding strong polymorph apis")
    polymorph = find_polymorph(d)
    print("Finding empty apis")
    empties = find_empties(d)
    print("Finding 0Sys apis")
    no_sys = find_no_syscall_apis(d)
    print("Finding 0IndSys apis")
    no_ind_sys = find_no_indirect_sys(d)
    apis = set(d.keys())
    print("Finding no-leaf apis")
    no_leaves = apis - leaves
    print("Finding weak monomorph apis")
    monomorph = apis - polymorph
    print("Finding 1+Sys apis")
    sys = apis - no_sys
    print("Finding 1+IndSys apis")
    ind_sys = apis - no_ind_sys
    print("Finding weak polymorph")
    weak_polymorph = find_weak_polymorph(d)
    print("Finding strong monomorph apis")
    strong_monomorph = apis - weak_polymorph
    print("Building models for strong monomorph apis")
    precise_models = build_precise_models(d, strong_monomorph)
    print("Building models for implicit monomorph apis")
    implicit_precise_models = find_implicit_monomorph_models(d, precise_models)
    print("Finding empty/non-empty models")
    empty_models = {api for api, model in implicit_precise_models.items()
                    if len(model) == 0}
    non_empty_models = {api: model
                        for api, model in implicit_precise_models.items()
                        if api not in empty_models}
    strong_monomorph |= set(implicit_precise_models.keys())

    # checks that no_ind_sys is a subset of no_sys
    check_0sys(no_sys, no_ind_sys)
    check_polymorph(weak_polymorph, polymorph)
    check_empties_have_precise_model(empties, precise_models)
    check_implicit_precise_models(implicit_precise_models, precise_models)
    check_empties_have_empty_model(empties, empty_models)

    kb = prune_kb_from_empties(d, empty_models)

    with open('kb_no_empties.pickle', 'wb') as pf:
        pickle.dump(kb, pf)
        pickle.dump(syscalls, pf)

    with open(symbols_file, 'wb') as pf:
        pickle.dump(set(kb.keys()), pf)
        pickle.dump(syscalls, pf)

def load_kb_no_empties():
    global kb
    global syscalls
    global apis
    global regexes
    global regexes_test
    global test_results
    global models
    global kb_file
    global regex_file
    global models_file
    global symbols_file
    global leaf_models
    global models2

    print("Loading KB")
    with open(kb_file, "rb") as pf:
        sys.modules['classes'] = classes
        kb= pickle.load(pf)
        syscalls = pickle.load(pf)

    print("Loading symbols")
    apis, syscalls = load_symbols(symbols_file)

    kb = prune_kb_from_signals(kb)
    # print("Loading regexes")
    # f = open(regex_file, 'rb')
    # regexes_test = pickle.load(f)
    # f.close()
    # regexes, test_results = regexes_split_test_results(regexes_test)

    print("Loading generic models")
    models = load_models(models_file)

    print("Loading not-so-generic models")
    models2 = load_models(models2_file)

    symbols_generator(apis | syscalls.keys())
    leaf_models = find_leaves_models(models, syscalls)

if __name__ == '__main__':
    if (not Path(kb_file).is_file()
        or not Path(models_file).is_file()
        or not Path(symbols_file).is_file()):
        first_run()
    else:
        load_kb_no_empties()

