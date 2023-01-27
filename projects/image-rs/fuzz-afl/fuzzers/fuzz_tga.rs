extern crate afl;
extern crate image;

use std::io::Cursor;

use image::{DynamicImage, ImageDecoder};
use image::error::{ImageError, ImageResult, LimitError, LimitErrorKind};

#[inline(always)]
fn tga_decode(data: &[u8]) -> ImageResult<DynamicImage> {
    let cursor = Cursor::new(data);
    let decoder = image::codecs::tga::TgaDecoder::new(cursor)?;
    let (width, height) = decoder.dimensions();

    if width.saturating_mul(height) > 4_000_000 {
        return Err(ImageError::Limits(LimitError::from_kind(LimitErrorKind::DimensionError)));
    }

    DynamicImage::from_decoder(decoder)
}

fn main() {
    afl::fuzz(true, |data| {
        let _ = tga_decode(&data);
    });
}
