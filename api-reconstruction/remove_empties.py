#!/usr/bin/env python3
from analysis import *

def prune():
    kb = {}
    apis = {}
    syscalls = {}
    kb_file = "pruned_db.pickle"
    kb_new_file = 'kb_no_empties.pickle'

    if not Path(kb_file).is_file():
        print("Error: No KB file found", file=sys.stderr)
        sys.exit(1)
    with open(kb_file, "rb") as pf:
        d = pickle.load(pf)
        syscalls = pickle.load(pf)

    print("Finding weak polymorph")
    weak_polymorph = find_weak_polymorph(d)
    print("Finding strong monomorph apis")
    strong_monomorph = apis.keys() - weak_polymorph
    print("Building models for strong monomorph apis")
    precise_models = build_precise_models(d, strong_monomorph)
    print("Building models for implicit monomorph apis")
    implicit_precise_models = find_implicit_monomorph_models(d, precise_models)
    print("Finding empty/non-empty models")
    empty_models = {api for api, model in implicit_precise_models.items()
                    if len(model) == 0}

    kb = prune_kb_from_empties(d, empty_models)
    kb_remove_hanging_calls(kb)
    with open(kb_new_file, 'wb') as pf:
        pickle.dump(kb, pf)
        pickle.dump(syscalls, pf)

if __name__ == "__main__":
    prune()
