all: fuzzers sydr

fuzzers: zip_fuzzer large_fuzzer compress_fuzzer uncompress_fuzzer small_fuzzer

sydr: zip_sydr large_sydr compress_sydr uncompress_sydr small_sydr

miniz.o: miniz.c miniz.h
	clang -g -fsanitize=fuzzer-no-link,address,undefined -c miniz.c -o miniz.o

%_fuzzer: miniz.o %_fuzzer.c
	clang -g -fsanitize=fuzzer,address,undefined -c $@.c -o $@.o
	clang -g -fsanitize=fuzzer,address,undefined $@.o miniz.o -o $@

miniz_sydr.o: miniz.c miniz.h
	clang -g -c miniz.c -o miniz_sydr.o

fuzz_main.o: fuzz_main.c
	clang -g -c fuzz_main.c -o fuzz_main.o

%_sydr: miniz_sydr.o fuzz_main.o
	for f in ./*_fuzzer.c; do \
		clang -g  -c $${f}  -o $@.o ; \
		clang -g  $@.o miniz_sydr.o fuzz_main.o -o $@ ; \
	done
clean:
	rm -rf *.o *_fuzzer *_sydr
