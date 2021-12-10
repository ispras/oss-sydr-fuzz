# TensorFlow

TensorFlow is an Open Source platform for machine learning. It has a comprehensive, flexible ecosystem of tools, libraries and community resources that lets researchers push the state-of-the-art in ML and developers easily build and deploy ML powered applications.

## Build Docker

	$ sudo docker build -t oss-sydr-fuzz-tensorflow .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/tensorflow` directory:

	$ unzip sydr.zip

Run Docker:

	$ docker run --rm -it -v `pwd`:/fuzz oss-sydr-fuzz-tensorflow /bin/bash

Change the directory to `/fuzz`:

	# cd /fuzz

Run hybrid fuzzing

	# sydr-fuzz -c cleanpath_fuzz.toml run -l debug

## Alternative Fuzz Targets

TensorFlow project has 11 fuzz targets.

### arg\_def\_case\_fuzz

	# sydr-fuzz -c arg_def_case_fuzz.toml run -l debug

### base64\_fuzz

	# sydr-fuzz -c base64_fuzz.toml run -l debug

### cleanpath\_fuzz

	# sydr-fuzz -c cleanpath_fuzz.toml run -l debug

### consume\_leading\_digits\_fuzz

	# sydr-fuzz -c consume_leading_digits_fuzz.toml run -l debug

### joinpath\_fuzz

	# sydr-fuzz -c joinpath_fuzz.toml run -l debug

### parseURI\_fuzz

	# sydr-fuzz -c parseURI_fuzz.toml run -l debug

### status\_fuzz

	# sydr-fuzz -c status_fuzz.toml run -l debug

### status\_group\_fuzz

	# sydr-fuzz -c status_group_fuzz.toml run -l debug

### string\_replace\_fuzz

	# sydr-fuzz -c string_replace_fuzz.toml run -l debug

### stringprintf\_fuzz

	# sydr-fuzz -c stringprintf_fuzz.toml run -l debug

### tstring\_fuzz

	# sydr-fuzz -c tstring_fuzz.toml run -l debug

