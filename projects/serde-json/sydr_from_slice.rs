use std::env;
use std::fs::File;
use std::io::Read;

use serde_json::{from_slice, Value};

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() >= 2 {
        let filename = &args[1];
        let mut f = File::open(filename).expect("no file found");
        let metadata = std::fs::metadata(filename).expect("unable to read metadata");
        let mut data = vec![0; metadata.len() as usize];
        f.read(&mut data).expect("buffer overflow");

        _ = from_slice::<Value>(&data);
    }

    Ok(())
}

