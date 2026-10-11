//! The worker entry point and the decode primitives it uses.

use std::io::{Cursor, Read, Write};
use std::path::Path;

use crate::PreviewError;
use crate::sandbox;

/// Maximum input file size the worker will read.
pub const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;
/// Maximum decoded image dimensions (decompression-bomb guard).
pub const MAX_IMAGE_DIM: u32 = 16_384;
/// Maximum decoder allocation.
pub const MAX_IMAGE_ALLOC: u64 = 256 * 1024 * 1024;
/// Maximum text preview size.
pub const MAX_TEXT_BYTES: usize = 64 * 1024;

/// Decodes `data` and produces a PNG thumbnail whose longest side is at
/// most `max_dim` pixels. Shared by the worker and the fuzz target.
pub fn decode_thumbnail(data: &[u8], max_dim: u32) -> Result<Vec<u8>, PreviewError> {
    let mut reader = image::ImageReader::new(Cursor::new(data)).with_guessed_format()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIM);
    limits.max_image_height = Some(MAX_IMAGE_DIM);
    limits.max_alloc = Some(MAX_IMAGE_ALLOC);
    reader.limits(limits);
    let image = reader.decode()?;
    let size = max_dim.clamp(16, 2048);
    let thumbnail = image.thumbnail(size, size);
    let mut out = Vec::new();
    thumbnail.write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)?;
    Ok(out)
}

/// A UTF-8 (lossy) head of `data`, at most [`MAX_TEXT_BYTES`].
pub fn text_head(data: &[u8]) -> String {
    let head = &data[..data.len().min(MAX_TEXT_BYTES)];
    String::from_utf8_lossy(head).into_owned()
}

/// Runs the worker: harden, read the input, produce the preview, write it
/// to stdout. Called from the server binary's hidden `preview-worker`
/// subcommand.
pub fn run(kind: &str, input: &Path, max_dim: u32) -> Result<(), PreviewError> {
    let hardening = sandbox::harden(input);
    eprintln!(
        "preview-worker: kind={kind} rlimits={} nnp={} landlock={} seccomp={}",
        hardening.rlimits, hardening.no_new_privs, hardening.landlock_abi, hardening.seccomp
    );

    let metadata = std::fs::metadata(input)?;
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(PreviewError::Unsupported);
    }
    let mut data = Vec::with_capacity(metadata.len() as usize);
    std::fs::File::open(input)?.read_to_end(&mut data)?;

    let output = match kind {
        "image" => decode_thumbnail(&data, max_dim)?,
        "text" => text_head(&data).into_bytes(),
        _ => return Err(PreviewError::Unsupported),
    };
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&output)?;
    stdout.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageFormat, RgbImage};

    fn png(width: u32, height: u32) -> Vec<u8> {
        let image = RgbImage::from_fn(width, height, |x, y| {
            image::Rgb([(x % 256) as u8, (y % 256) as u8, 128])
        });
        let mut out = Vec::new();
        image
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    #[test]
    fn thumbnails_images_to_png_within_bounds() {
        let source = png(800, 400);
        let thumb = decode_thumbnail(&source, 64).unwrap();
        let decoded = image::load_from_memory_with_format(&thumb, ImageFormat::Png).unwrap();
        assert!(decoded.width() <= 64);
        assert!(decoded.height() <= 64);
        assert!(decoded.width() >= decoded.height());
    }

    #[test]
    fn rejects_garbage_and_oversized_dimensions() {
        assert!(decode_thumbnail(b"not an image", 64).is_err());

        // Wider than the decompression-bomb guard allows (still cheap to
        // encode: one row of pixels).
        let wide = png(20_000, 1);
        assert!(decode_thumbnail(&wide, 64).is_err());
    }

    #[test]
    fn text_head_is_lossy_and_capped() {
        let text = text_head(b"hello \xffworld");
        assert!(text.starts_with("hello "));
        let long = text_head(&vec![b'a'; MAX_TEXT_BYTES * 2]);
        assert_eq!(long.len(), MAX_TEXT_BYTES);
    }
}
