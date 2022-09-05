extern crate goblin;

use std::env;
use std::fs::File;
use std::io::Read;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() >= 2 {
        let filename = &args[1];
        let mut f = File::open(filename).expect("no file found");
        let metadata = std::fs::metadata(filename).expect("unable to read metadata");
        let mut data = vec![0; metadata.len() as usize];
        f.read(&mut data).expect("buffer overflow");
        if let Ok(elf) = goblin::elf::Elf::parse(&data) {
            for section_header in &elf.section_headers {
                let _ = elf.shdr_strtab.get(section_header.sh_name);
            }

            for _relocation in &elf.dynrels {}

            if let Some(mut it) = elf.iter_note_headers(&data) {
                while let Some(Ok(_a)) = it.next() {}
            }

            if let Some(mut it) = elf.iter_note_sections(&data, None) {
                while let Some(Ok(_a)) = it.next() {}
            }

            if let Some(mut it) = elf.iter_note_sections(&data, Some("x")) {
                while let Some(Ok(_a)) = it.next() {}
            }
        }
    }

    Ok(())
}

