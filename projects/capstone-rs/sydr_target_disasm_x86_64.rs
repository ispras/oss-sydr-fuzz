extern crate capstone;

use std::env;
use std::fs::File;
use std::io::Read;

use capstone::prelude::*;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() >= 2 {
        let filename = &args[1];
        let mut f = File::open(filename).expect("no file found");
        let metadata = std::fs::metadata(filename).expect("unable to read metadata");
        let mut data = vec![0; metadata.len() as usize];
        f.read(&mut data).expect("buffer overflow");

        let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()
        .unwrap();
        for i in cs.disasm_all(&data, 0x1000).unwrap().iter() {
            let detail: InsnDetail = cs.insn_detail(&i).unwrap();
            let arch_detail: ArchDetail = detail.arch_detail();
            arch_detail.operands().iter().for_each(drop);
            detail.regs_read().iter().for_each(drop);
            detail.regs_write().iter().for_each(drop);
            detail.groups().iter().for_each(drop);
        }
    }

    Ok(())
}

