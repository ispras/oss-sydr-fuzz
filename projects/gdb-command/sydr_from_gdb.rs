extern crate gdb_command;

use std::env;
use std::fs::File;
use std::io::Read;

use gdb_command::mappings::{MappedFiles, MappedFilesExt};
use gdb_command::memory::MemoryObject;
use gdb_command::registers::{Registers, RegistersExt};
use gdb_command::siginfo::Siginfo;
use gdb_command::stacktrace::{Stacktrace, StacktraceExt};

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() >= 2 {
        let filename = &args[1];
        let mut f = File::open(filename).expect("no file found");
        let metadata = std::fs::metadata(filename).expect("unable to read metadata");
        let mut data = vec![0; metadata.len() as usize];
        f.read(&mut data).expect("buffer overflow");

        if data.len() < 2 {
            return Ok(());
        }

        let s = String::from_utf8_lossy(&data[1..]);
        match data[0] % 5 {
            0 => _ = Stacktrace::from_gdb(&s),
            1 => _ = Registers::from_gdb(&s),
            2 => _ = MappedFiles::from_gdb(&s),
            3 => _ = Siginfo::from_gdb(&s),
            _ => _ = MemoryObject::from_gdb(&s),
        }
    }

    Ok(())
}

