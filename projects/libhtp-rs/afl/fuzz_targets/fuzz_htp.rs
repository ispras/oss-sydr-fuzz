#[macro_use]
extern crate afl;
extern crate htp;

use htp::test::{Test, TestConfig};
use std::env;

fn main() {
    fuzz!(|data: &[u8]| {
        let mut t = Test::new(TestConfig());
        t.run_slice(data);
    });
}