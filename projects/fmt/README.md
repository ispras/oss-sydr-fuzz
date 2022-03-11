# Fmt

{fmt} is an open-source formatting library providing a fast and safe alternative
to C stdio and C++ iostreams.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-fmt .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/fmt` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-fmt /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

### Chrono_duration fuzzing

    # sydr-fuzz -c chrono_duration.toml run

Collect coverage report:

    # sydr-fuzz -c chrono_duration.toml cov-show -- -Xdemangler=c++filt -format=html > index-chrono_duration.html

### Named_arg fuzzing

    # sydr-fuzz -c named_arg.toml run

Collect coverage report:

    # sydr-fuzz -c named_arg.toml cov-show -- -Xdemangler=c++filt -format=html > index-named_arg.html

### One_arg fuzzing

    # sydr-fuzz -c one_arg.toml run

Collect coverage report:

    # sydr-fuzz -c one_arg.toml cov-show -- -Xdemangler=c++filt -format=html > index-one_arg.html

### Two_args fuzzing

    # sydr-fuzz -c two_args.toml run

Collect coverage report:

    # sydr-fuzz -c two_args.toml cov-show -- -Xdemangler=c++filt -format=html > index-two_args.html

### Sprintf fuzzing

    # sydr-fuzz -c sprintf.toml run

Collect coverage report:

    # sydr-fuzz -c sprintf.toml cov-show -- -Xdemangler=c++filt -format=html > index-sprintf.html
