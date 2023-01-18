extern crate vrl;
use std::str;
use vrl::prelude::value;
use vrl_stdlib::parse_csv::parse_csv;

fn main() {
    use std::io::{self, BufRead};
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let buffer = stdin.fill_buf().unwrap();
    let s = match str::from_utf8(buffer) {
        Ok(v) => v,
        Err(e) => return,
    };
    parse_csv(value!(s), value!(","));
}
