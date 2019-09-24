# syscall2api
This repo contains the code described in the paper "Exploring Syscall-Based Semantics Reconstruction of Android Applications" [1].  

## Repository structure  
### aosp-parser-modifier
This directory contains the code responsible for the source-code instrumentation of the Android framework.  
Note: aosp-parser-modifier depends on [JavaParser](https://github.com/javaparser/javaparser)  

### trace-collection
Here you will find scripts to run a set of apps on a device running an instrumented version of Android, and collect mixed API-Syscall traces.  
It requires `adb` to be installed and available in `$PATH`.  

### trace-parser
This directory contains `python` scripts that create the Knowledge-Base (KB) data-structure, by parsing execution traces.  

### api-reconstruction
This directory contains the scripts that perform various analyses on the KB.  
The most important scripts are:  
1. `prune_kb.py`: removes noise from the KB  
2. `remove_empties.py`: removes those APIs that do not call any syscall from the KB (helpful to reduce the size of the KB, making other analysis faster)  
3. `create_models.py`: creates models from the KB  
4. `eval_ambiguity.py`: measures the ambiguity of the API models (see Section 7.4 in [1])  
5. `match_assessment.py`: performs the matching algorithm on a list of syscall traces. It also measures the percentage of correct matches and the percentage of the length of the traces that are covered with correct matches.  

## Dataset
The relevant dataset used in our paper is available [here](http://crazyivan.s3.eurecom.fr:8888/syscall2api_dataset.tar.gz).

## References
[1] D. Nisi, A. Bianchi, Y. Fratantonio.
"Exploring Syscall-Based Semantics Reconstruction of Android Applications"
22nd International Symposium on Research in Attacks, Intrusions and Defenses
