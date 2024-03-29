extern crate image;

use std::env;
use std::fs::File;
use std::io::Read;
use std::io::Cursor;
use image::ImageResult;
use image::codecs::openexr::*;
use std::io::Seek;
use std::convert::TryFrom;
use image::ImageDecoder;
use image::ImageEncoder;
use image::ColorType;
use image::io::Limits;
use std::io::Write;

// "just dont panic"
fn roundtrip(bytes: &[u8]) -> ImageResult<()> {
    /// Read the file from the specified path into an `Rgba32FImage`.
    // TODO this method should probably already exist in the main image crate
    fn read_as_rgba_byte_image(read: impl Read + Seek) -> ImageResult<(u32, u32, Vec<u8>)> {
        let mut decoder = OpenExrDecoder::with_alpha_preference(read, Some(true))?;
        match usize::try_from(decoder.total_bytes()) {
            Ok(decoded_size) if decoded_size <= 256 * 1024 * 1024 => {
                decoder.set_limits(Limits::default())?;
                let (width, height) = decoder.dimensions();
                let mut buffer = vec![0; decoded_size];
                decoder.read_image(buffer.as_mut_slice())?;
                Ok((width, height, buffer))
            }
            _ => Err(image::ImageError::Limits(
                image::error::LimitError::from_kind(
                    image::error::LimitErrorKind::InsufficientMemory,
                ),
            )),
        }
    }

    /// Write an `Rgba32FImage`.
    /// Assumes the writer is buffered. In most cases,
    /// you should wrap your writer in a `BufWriter` for best performance.
    // TODO this method should probably already exist in the main image crate
    fn write_rgba_image(
        write: impl Write + Seek,
        (width, height, data): &(u32, u32, Vec<u8>),
    ) -> ImageResult<()> {
        OpenExrEncoder::new(write).write_image(data.as_slice(), *width, *height, ColorType::Rgba32F)
    }

    let decoded_image = read_as_rgba_byte_image(Cursor::new(bytes))?;

    let mut bytes = Vec::with_capacity(bytes.len() + 20);
    write_rgba_image(Cursor::new(&mut bytes), &decoded_image)?;

    let redecoded_image = read_as_rgba_byte_image(Cursor::new(bytes))?;

    // if both images are valid, assert read/write consistency
    assert_eq!(
        decoded_image, redecoded_image,
        "image was valid but was not reproducible"
    );
    Ok(())
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() >= 2 {
        let filename = &args[1];
        let mut f = File::open(filename).expect("no file found");
        let metadata = std::fs::metadata(filename).expect("unable to read metadata");
        let mut data = vec![0; metadata.len() as usize];
        f.read(&mut data).expect("buffer overflow");
        let _ = roundtrip(&data);
    }

    Ok(())
}

