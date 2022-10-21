#!/bin/bash -eu

patch_files() {
    for f in $files_to_patch
    do
	sed -i -e "s/std::out_of_range(\"Argument passed to at() was not in the map.\")/std::runtime_error()/g" $f
    done
}

cd /pytorch_fuzz

files_to_patch=$(grep -r 'Argument passed to at() was not in the map.' \
		 | xargs -I {} /bin/bash -c \
		 "echo -n \"{}\" | cut -d ':' -f 1" \
		 | grep -v "Binary file")

patch_files

cd /pytorch_sydr
patch_files

cd /pytorch_cov
patch_files
