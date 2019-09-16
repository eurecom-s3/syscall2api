import pickle
from .utils import *

def persist(file_name, indexes):
    indexes = tuple(sorted(indexes))
    def decorator(original_func):
        cache = load_cache(file_name)
        def new_func(*params):
            cacheentry = tupletostring(tuple(params[i] for i in indexes))
            if cacheentry not in cache:
                cache[cacheentry] = original_func(*params)
            return cache[cacheentry]
        return new_func
    return decorator
