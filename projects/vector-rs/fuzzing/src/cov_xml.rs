extern crate vrl;
use std::str;
use vrl::prelude::value;
use vrl_stdlib::parse_xml::parse_xml;
use vrl_stdlib::parse_xml::ParseOptions;

fn main() {
    use std::io::{self, BufRead};
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let buffer = stdin.fill_buf().unwrap();
    let s = match str::from_utf8(buffer) {
        Ok(v) => v,
        Err(e) => return,
    };
    let options = ParseOptions {
        trim: None,
        include_attr: None,
        attr_prefix: None,
        text_key: None,
        always_use_text_key: None,
        parse_bool: None,
        parse_null: None,
        parse_number: None,
    };
    println!("{:?}", parse_xml(value!(s), options));
}
