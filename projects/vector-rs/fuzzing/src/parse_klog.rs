extern crate vrl;
use std::str;
use vrl::prelude::value;
use vrl_stdlib::parse_klog::parse_klog;
#[macro_use]
extern crate afl;

fn main() {
    fuzz!(|data: &[u8]| {
        let s = match str::from_utf8(data) {
            Ok(v) => v,
            Err(e) => return,
        };
        vrl_stdlib::parse_klog::parse_klog(value!(s));
    })
}
