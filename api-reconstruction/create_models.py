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
kb_file = 'kb_no_empties.pickle'
regex_file = 'new_regex.pickle'
models_file = 'models.pickle'
symbols_file = 'symbols.pickle'
leaf_models = {}
modelclasses = set(["APIGenericModel", "APILessGenericModel"])

def create_models(cls):
    global kb
    global apis
    global syscalls
    global regexes
    global models
    global symbols_file

    if not Path(kb_file).is_file():
        print("Error: No KB file found", file=sys.stderr)
        sys.exit(1)
    with open(kb_file, "rb") as pf:
        kb = pickle.load(pf)
        kb = prune_kb_from_signals(kb)
        syscalls = pickle.load(pf)

    with open(symbols_file, "rb") as pf:
        apis = pickle.load(pf)

    symbols_generator(apis | syscalls.keys())
    if Path("models2.pickle").is_file():
        with open("models2.pickle", "rb") as pf:
            models = pickle.load(pf)
    else:
        models = {}
    cls.generate_models(kb, syscalls, models)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: %s <models type>" % sys.argv[0], file=sys.stderr)
        sys.exit(1)

    model_class = sys.argv[1]
    if model_class not in modelclasses:
        print("Available model types: " + ', '.join(modelclasses),
              file=sys.stderr)
        sys.exit(2)

    cls = eval(model_class)
    create_models(cls)
