extern crate afl;
extern crate image;

fn main() {
    afl::fuzz(true, |data| {
        let _ = image::load_from_memory(&data);
    });
}
