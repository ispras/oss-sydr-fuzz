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
        if data.len() < 2 {
            return Ok(()) ;
        }
        let split_point = data[0] as usize;
        if let Ok(data) = std::str::from_utf8(&data[1..]) {
            use std::cmp::max;
            // split data into regular expression and actual input to search through
            let len = data.chars().count();
            let split_off_point = max(split_point, 1) % len as usize;
            let char_index = data.char_indices().nth(split_off_point);
            if let Some((char_index, _)) = char_index {
                let (pattern, input) = data.split_at(char_index);
                if let Ok(re) = regex::Regex::new(pattern) {
                    re.is_match(input);
                }
            }
        }
    }

    Ok(())
}

