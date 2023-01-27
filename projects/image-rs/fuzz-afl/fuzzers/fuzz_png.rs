extern crate afl;
extern crate image;

use image::{DynamicImage, ImageDecoder};
use image::error::{ImageError, ImageResult, LimitError, LimitErrorKind};

#[inline(always)]
fn png_decode(data: &[u8]) -> ImageResult<DynamicImage> {
    let decoder = image::codecs::png::PngDecoder::new(data)?;
    let (width, height) = decoder.dimensions();

    if width.saturating_mul(height) > 4_000_000 {
        return Err(ImageError::Limits(LimitError::from_kind(LimitErrorKind::DimensionError)));
    }

    DynamicImage::from_decoder(decoder)
}

fn main() {
    afl::fuzz(true, |data| {
        let _ = png_decode(&data);
    });
}
