# fuzzywuzzy 

Fuzzy string matching for java based on the FuzzyWuzzy Python algorithm.
The algorithm uses Levenshtein distance to calculate similarity between strings.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-fuzzywuzzy .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/fuzzywuzzy` directory:

    $ unzip sydr.zip

Run Docker:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-fuzzywuzzy /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run fuzzing:

    # sydr-fuzz -c DiffUtilsFuzzer.toml run

Minimize corpus:

    # sydr-fuzz -c DiffUtilsFuzzer.toml cmin 

Collect and report coverage:

    # sydr-fuzz -c DiffUtilsFuzzer.toml cov-html -s /fuzzywuzzy/diffutils/src/:/fuzzywuzzy/src/

## Alternative Fuzz Targets

fuzzywuzzy project has 2 fuzz targets.

### DiffUtilsFuzzer

    # sydr-fuzz -c DiffUtilsFuzzer.toml run

### FuzzySearchFuzzer

    # sydr-fuzz -c FuzzySearchFuzzer.toml run
