# ICU

ICU stands for the International Components for Unicode. The ICU project is under the stewardship of The Unicode Consortium.

## Build Docker

    $ sudo docker build -t oss-sydr-fuzz-icu .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/icu` directory:

    $ unzip sydr.zip

Run docker:

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro --rm -it -v $PWD:/fuzz oss-sydr-fuzz-icu /bin/bash

Change directory to `/fuzz`:

    # cd /fuzz

Run hybrid fuzzing:

    # sydr-fuzz -c break_iterator.toml run

Minimize corpus:

    # sydr-fuzz -c break_iterator.toml cmin

Collect coverage:

    # sydr-fuzz -c break_iterator.toml cov-export -- -format=lcov > icu.lcov
    # genhtml -o icu icu.lcov

Check security predicates:

    # sydr-fuzz -c break_iterator.toml security

## Supported Targets

    * break_iterator
    * collator_compare
    * collator_rulebased
    * converter
    * locale
    * number_format
    * ucasemap
    * uloc_canonicalize
    * uloc_for_language_tag
    * uloc_get_name
    * uloc_is_right_to_left
    * uloc_open_keywords
    * unicode_string_codepage_create
    * uregex_open
