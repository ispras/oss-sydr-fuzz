extern crate vrl;
use std::str;
use vrl::prelude::value;
use vrl_stdlib::parse_aws_alb_log::parse_aws_alb_log;
fn main() {
    use std::io::{self, BufRead};
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let buffer = stdin.fill_buf().unwrap();
    let s = match str::from_utf8(buffer) {
        Ok(v) => v,
        Err(e) => return,
    };
    parse_aws_alb_log(value!(s));
}
