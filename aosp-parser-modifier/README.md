# aosp-parser-modifier

This module parses and modifies automatically the source code of AOSP. 
It instruments the implementation of each API in order to provide a logging functionality.

## Build
The .project file can be used to import the module in Eclipse. 
To build the project, use the pom.xml and build_concurrent.xml configuration files, that produce the single-threaded and the multi-threaded version of the program respectively.

## Run
You can use parse\_aosp.sh and parse\_aosp\_fast.sh in scripts/ to instrument the AOSP code.
