CXXFLAGS += -g -O0 -std=c++11 -DGTEST_USE_OWN_TR1_TUPLE -I../.. -I. -Wall -Wextra -Wtype-limits -Wconversion

OPENSSL_DIR = /usr/local/opt/openssl@1.1

OPENSSL_SUPPORT = -DCPPHTTPLIB_OPENSSL_SUPPORT -I$(OPENSSL_DIR)/include -I$(OPENSSL_DIR)/lib  /usr/local/lib/libssl.a /usr/local/lib/libcrypto.a

ZLIB_SUPPORT = -DCPPHTTPLIB_ZLIB_SUPPORT -lz

BROTLI_DIR = /usr/local/opt/brotli

FUZZERS = server_fuzzer url_parser_fuzzer header_parser_fuzzer client_fuzzer multipart_parser_fuzzer

all : $(FUZZERS)

server_fuzzer : server_fuzzer.cc ../../httplib.h
	$(CXX) $(CXXFLAGS) -o $@  $<  $(ZLIB_SUPPORT)  -pthread -lanl
	zip -q -r server_fuzzer_seed_corpus.zip corpus

client_fuzzer : client_fuzzer.cc ../../httplib.h
	$(CXX) $(CXXFLAGS) -o $@  $<  $(ZLIB_SUPPORT) -pthread -lanl
	zip -q -r client_fuzzer_seed_corpus.zip corpus

header_parser_fuzzer : header_parser_fuzzer.cc ../../httplib.h
	$(CXX) $(CXXFLAGS) -o $@  $<  $(ZLIB_SUPPORT) -pthread -lanl

url_parser_fuzzer : url_parser_fuzzer.cc ../../httplib.h
	$(CXX) $(CXXFLAGS) -o $@  $<  $(ZLIB_SUPPORT) -pthread -lanl

multipart_parser_fuzzer : multipart_parser_fuzzer.cc ../../httplib.h
	$(CXX) $(CXXFLAGS) -o $@  $<  $(ZLIB_SUPPORT) -pthread -lanl

clean:
	rm -f server_fuzzer client_fuzzer header_parser_fuzzer url_parser_fuzzer multipart_parser_fuzzer pem *.0 *.o *.1 *.srl *.zip
