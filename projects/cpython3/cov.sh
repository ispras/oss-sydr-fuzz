for j in $(cat ./fuzz_tests.txt); do for i in $(ls corpus | sort); do LLVM_PROFILE_FILE="/cov/tmpcov/$i.profraw" /cov/$j $i -runs=1; done; done
for i in /cov/tmpcov/*; do llvm-profdata merge $i -o /cov/$i.profdata; done
llvm-profdata merge /cov/tmpcov/*.profdata  -o /cov/python.profdata
llvm-cov show --instr-profile /cov/python.profdata /cpython3/python -output-dir coverage -format=html
