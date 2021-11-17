extern crate image;

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
        let _ = decode(&data);
    }

    Ok(())
}

fn decode(data: &[u8]) -> Result<(), image::ImageError> {
    use image::ImageDecoder;
    let decoder = image::codecs::tga::TgaDecoder::new(std::io::Cursor::new(data))?;
    if decoder.total_bytes() > 4_000_000 {
        return Ok(());
    }
    let mut buffer = vec![0; decoder.total_bytes() as usize];
    decoder.read_image(&mut buffer)?;
    Ok(())
}
