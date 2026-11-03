//! The `attributedBody` typedstream decoder (G2).
//!
//! Ventura and later store a message's content in `attributedBody` — an
//! `NSAttributedString` serialized by Apple's typedstream archiver — and leave
//! `text` NULL. Only that one field is decoded here, with a hard size bound and
//! no indexing that can panic: every slice goes through `get`.
//!
//! The layout is the well-documented marker approach: the UTF-8 payload sits
//! after the two-byte start marker `01 2B` and a variable-length prefix
//! (`<= 0x7F` literal, `0x81` = little-endian `u16`, `0x82` = little-endian
//! `u32`). The length is authoritative; the decoder never scans for an end
//! marker, because byte pairs like `86 84` occur inside valid UTF-8.
//!
//! A blob that is not a typedstream, is too large, has no marker, has a bad
//! length, or is not valid UTF-8 is an error. The caller counts and skips it;
//! the content is never logged.

use std::fmt;

/// Largest `attributedBody` this decoder will look at (1 MiB). Anything larger
/// is skipped rather than walked.
pub const MAX_ATTRIBUTED_BODY: usize = 1 << 20;

/// The typedstream archiver header.
const TYPEDSTREAM_MAGIC: &[u8] = b"\x04\x0bstreamtyped";

/// The start-of-text marker (`0x2B` is the C-string type tag).
const TEXT_MARKER: [u8; 2] = [0x01, 0x2b];

/// Why an `attributedBody` could not be decoded. Carries no bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributedError {
    /// The blob exceeds [`MAX_ATTRIBUTED_BODY`].
    TooLarge,
    /// The blob does not start with the typedstream header.
    NotTypedStream,
    /// No start-of-text marker was found.
    NoText,
    /// The length prefix or payload runs past the end of the blob.
    BadLength,
    /// The payload is not valid UTF-8.
    BadUtf8,
}

impl fmt::Display for AttributedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "attributedBody is over the size bound",
            Self::NotTypedStream => "attributedBody is not a typedstream",
            Self::NoText => "attributedBody carries no text marker",
            Self::BadLength => "attributedBody length is out of bounds",
            Self::BadUtf8 => "attributedBody text is not valid UTF-8",
        })
    }
}

impl std::error::Error for AttributedError {}

/// Decode the text of a typedstream `attributedBody` blob.
///
/// Bounded and panic-free: it returns `Err` for anything it cannot prove it
/// understands. An empty string is a valid decode (the caller drops it).
pub fn decode_attributed_body(blob: &[u8]) -> Result<String, AttributedError> {
    if blob.len() > MAX_ATTRIBUTED_BODY {
        return Err(AttributedError::TooLarge);
    }
    if !blob.starts_with(TYPEDSTREAM_MAGIC) {
        return Err(AttributedError::NotTypedStream);
    }
    let marker = blob
        .windows(TEXT_MARKER.len())
        .position(|window| window == TEXT_MARKER)
        .ok_or(AttributedError::NoText)?;
    let rest = blob
        .get(marker + TEXT_MARKER.len()..)
        .ok_or(AttributedError::NoText)?;
    let (length, header) = read_length(rest)?;
    let end = header
        .checked_add(length)
        .ok_or(AttributedError::BadLength)?;
    let raw = rest.get(header..end).ok_or(AttributedError::BadLength)?;
    let text = std::str::from_utf8(raw).map_err(|_| AttributedError::BadUtf8)?;
    Ok(text.to_string())
}

/// Read the variable-length prefix; returns `(length, bytes consumed)`.
fn read_length(rest: &[u8]) -> Result<(usize, usize), AttributedError> {
    let first = *rest.first().ok_or(AttributedError::BadLength)?;
    match first {
        0x81 => {
            let bytes = rest.get(1..3).ok_or(AttributedError::BadLength)?;
            Ok((usize::from(u16::from_le_bytes([bytes[0], bytes[1]])), 3))
        }
        0x82 => {
            let bytes = rest.get(1..5).ok_or(AttributedError::BadLength)?;
            Ok((
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize,
                5,
            ))
        }
        literal if literal <= 0x7f => Ok((usize::from(literal), 1)),
        _ => Err(AttributedError::BadLength),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Build a typedstream blob the way Messages writes one.
    fn blob_for(text: &str) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend_from_slice(TYPEDSTREAM_MAGIC);
        blob.extend_from_slice(b"\x81\xe8\x03\x84\x01\x40\x84\x84\x84\x12NSAttributedString\x00");
        blob.extend_from_slice(b"\x84\x84\x08NSObject\x00\x85\x92\x84\x84\x84\x08NSString");
        blob.extend_from_slice(&TEXT_MARKER);
        let bytes = text.as_bytes();
        match bytes.len() {
            n if n <= 0x7f => blob.push(n as u8),
            n if n <= usize::from(u16::MAX) => {
                blob.push(0x81);
                blob.extend_from_slice(&(n as u16).to_le_bytes());
            }
            n => {
                blob.push(0x82);
                blob.extend_from_slice(&(n as u32).to_le_bytes());
            }
        }
        blob.extend_from_slice(bytes);
        blob.extend_from_slice(b"\x86\x84");
        blob
    }

    /// A real `attributedBody` captured from a macOS `chat.db`, shared by the
    /// MIT-licensed parsers this decoder follows. Decodes to
    /// `"Testing with imsg installed"`.
    const REAL_BLOB_TESTING: &[u8] = &[
        0x04, 0x0B, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6D, 0x74, 0x79, 0x70, 0x65, 0x64, 0x81, 0xE8,
        0x03, 0x84, 0x01, 0x40, 0x84, 0x84, 0x84, 0x12, 0x4E, 0x53, 0x41, 0x74, 0x74, 0x72, 0x69,
        0x62, 0x75, 0x74, 0x65, 0x64, 0x53, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x00, 0x84, 0x84, 0x08,
        0x4E, 0x53, 0x4F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x00, 0x85, 0x92, 0x84, 0x84, 0x84, 0x08,
        0x4E, 0x53, 0x53, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x01, 0x94, 0x84, 0x01, 0x2B, 0x1B, 0x54,
        0x65, 0x73, 0x74, 0x69, 0x6E, 0x67, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x69, 0x6D, 0x73,
        0x67, 0x20, 0x69, 0x6E, 0x73, 0x74, 0x61, 0x6C, 0x6C, 0x65, 0x64, 0x86, 0x84, 0x02, 0x69,
        0x49, 0x01, 0x1B, 0x92, 0x84, 0x84, 0x84, 0x0C, 0x4E, 0x53, 0x44, 0x69, 0x63, 0x74, 0x69,
        0x6F, 0x6E, 0x61, 0x72, 0x79, 0x00, 0x94, 0x84, 0x01, 0x69, 0x01, 0x92, 0x84, 0x96, 0x96,
        0x1D, 0x5F, 0x5F, 0x6B, 0x49, 0x4D, 0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x50, 0x61,
        0x72, 0x74, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x4E, 0x61, 0x6D, 0x65,
        0x86, 0x92, 0x84, 0x84, 0x84, 0x08, 0x4E, 0x53, 0x4E, 0x75, 0x6D, 0x62, 0x65, 0x72, 0x00,
        0x84, 0x84, 0x07, 0x4E, 0x53, 0x56, 0x61, 0x6C, 0x75, 0x65, 0x00, 0x94, 0x84, 0x01, 0x2A,
        0x84, 0x99, 0x99, 0x00, 0x86, 0x86, 0x86,
    ];

    #[test]
    fn the_real_world_blob_decodes() {
        assert_eq!(
            decode_attributed_body(REAL_BLOB_TESTING).unwrap(),
            "Testing with imsg installed"
        );
    }

    #[test]
    fn a_round_trip_blob_decodes() {
        assert_eq!(
            decode_attributed_body(&blob_for("Bonjour l'équipe")).unwrap(),
            "Bonjour l'équipe"
        );
    }

    #[test]
    fn a_long_two_byte_length_decodes() {
        let text = "A".repeat(300);
        assert_eq!(decode_attributed_body(&blob_for(&text)).unwrap(), text);
    }

    #[test]
    fn a_four_byte_length_decodes() {
        let mut blob = Vec::new();
        blob.extend_from_slice(TYPEDSTREAM_MAGIC);
        blob.extend_from_slice(&TEXT_MARKER);
        blob.push(0x82);
        blob.extend_from_slice(&5u32.to_le_bytes());
        blob.extend_from_slice(b"Hello");
        assert_eq!(decode_attributed_body(&blob).unwrap(), "Hello");
    }

    #[test]
    fn an_empty_string_is_a_valid_decode() {
        assert_eq!(decode_attributed_body(&blob_for("")).unwrap(), "");
    }

    #[test]
    fn a_blob_without_the_typedstream_header_is_refused() {
        assert_eq!(
            decode_attributed_body(b"just some random bytes with 01 2b in it"),
            Err(AttributedError::NotTypedStream)
        );
    }

    #[test]
    fn a_truncated_payload_is_refused() {
        let mut blob = blob_for("hello");
        blob.truncate(blob.len() - 4);
        assert_eq!(
            decode_attributed_body(&blob),
            Err(AttributedError::BadLength)
        );
    }

    #[test]
    fn an_unobserved_length_tag_is_refused() {
        let mut blob = Vec::new();
        blob.extend_from_slice(TYPEDSTREAM_MAGIC);
        blob.extend_from_slice(&TEXT_MARKER);
        blob.push(0x83);
        blob.extend_from_slice(b"x");
        assert_eq!(
            decode_attributed_body(&blob),
            Err(AttributedError::BadLength)
        );
    }

    #[test]
    fn invalid_utf8_is_refused() {
        let mut blob = Vec::new();
        blob.extend_from_slice(TYPEDSTREAM_MAGIC);
        blob.extend_from_slice(&TEXT_MARKER);
        blob.push(2);
        blob.extend_from_slice(&[0xff, 0xfe]);
        assert_eq!(decode_attributed_body(&blob), Err(AttributedError::BadUtf8));
    }

    #[test]
    fn an_oversized_blob_is_refused_before_it_is_walked() {
        let blob = vec![0u8; MAX_ATTRIBUTED_BODY + 1];
        assert_eq!(
            decode_attributed_body(&blob),
            Err(AttributedError::TooLarge)
        );
    }

    proptest! {
        /// Fuzz-style: any bytes, including ones that start with the real
        /// header, must decode or return an error — never panic.
        #[test]
        fn arbitrary_bytes_never_panic(prefix in any::<bool>(), tail in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let mut blob = Vec::new();
            if prefix {
                blob.extend_from_slice(TYPEDSTREAM_MAGIC);
            }
            blob.extend_from_slice(&tail);
            let _ = decode_attributed_body(&blob);
        }
    }
}
