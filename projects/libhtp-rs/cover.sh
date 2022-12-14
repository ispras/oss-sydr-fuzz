mkdir /cover

export LLVM_PROFILE_FILE=/cover/"code-%p.profraw"

for file in $1/*
do
    /cover_fuzz_htp_rs $file
done

grcov . -s . --binary-path libhtp-rs/sydr_and_cover/target/debug/ -t html --branch --ignore-not-existing -o /fuzz/html_cover
