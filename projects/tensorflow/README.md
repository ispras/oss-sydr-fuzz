# TensorFlow

TensorFlow is an Open Source platform for machine learning. It has a comprehensive, flexible ecosystem of tools, libraries and community resources that lets researchers push the state-of-the-art in ML and developers easily build and deploy ML powered applications.

## Build Docker

	$ sudo docker build -t oss-sydr-fuzz-tensorflow .

## Run Hybrid Fuzzing

Unzip Sydr (`sydr.zip`) in `projects/tensorflow` directory:

	$ unzip sydr.zip

Run Docker:

        $ sudo docker run -v /etc/localtime:/etc/localtime:ro --privileged --network host --rm -it -v $PWD:/fuzz oss-sydr-fuzz-tensorflow /bin/bash

Change the directory to `/fuzz`:

	# cd /fuzz

Run hybrid fuzzing

	# sydr-fuzz -c cleanpath_fuzz.toml run -l debug

## Alternative Fuzz Targets

TensorFlow project has 11 fuzz targets.

### arg_def_case_fuzz

	# sydr-fuzz -c arg_def_case_fuzz.toml run -l debug

### base64_fuzz

	# sydr-fuzz -c base64_fuzz.toml run -l debug

### cleanpath_fuzz

	# sydr-fuzz -c cleanpath_fuzz.toml run -l debug

### consume_leading_digits_fuzz

	# sydr-fuzz -c consume_leading_digits_fuzz.toml run -l debug

### joinpath_fuzz

	# sydr-fuzz -c joinpath_fuzz.toml run -l debug

### parseURI_fuzz

	# sydr-fuzz -c parseURI_fuzz.toml run -l debug

### status_fuzz

	# sydr-fuzz -c status_fuzz.toml run -l debug

### status_group_fuzz

	# sydr-fuzz -c status_group_fuzz.toml run -l debug

### string_replace_fuzz

	# sydr-fuzz -c string_replace_fuzz.toml run -l debug

### stringprintf_fuzz

	# sydr-fuzz -c stringprintf_fuzz.toml run -l debug

### tstring_fuzz

	# sydr-fuzz -c tstring_fuzz.toml run -l debug

