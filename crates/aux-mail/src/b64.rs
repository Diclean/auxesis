//! Minimal RFC 4648 base64, hand-rolled.
//!
//! The connector needs base64 twice — the SMTP `AUTH` exchange and the MIME
//! `Content-Transfer-Encoding` — and the work order allows no new dependency.
//! Both uses are the standard alphabet with padding, so a ~40-line encoder is
//! smaller than the dependency edge it would otherwise add.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64, padded, with no line breaks.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Standard base64 wrapped at `width` characters, CRLF-terminated.
///
/// A body part's `Content-Transfer-Encoding` is base64 exactly so no encoded
/// line can approach the SMTP line limit; this wraps at 76 by construction.
/// The trailing CRLF makes the part end on its own line.
pub(crate) fn encode_lines(bytes: &[u8], width: usize) -> String {
    debug_assert!(width >= 4 && width.is_multiple_of(4));
    let encoded = encode(bytes);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / width * 2 + 2);
    for chunk in encoded.as_bytes().chunks(width) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push_str("\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_matches_the_rfc_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(input.as_bytes()), expected, "{input:?}");
        }
        // A byte above ASCII round-trips as its own octets, never as text.
        assert_eq!(encode(&[0xff, 0x00, 0x10]), "/wAQ");
    }

    #[test]
    fn line_wrapping_is_at_most_width_and_crlf_terminated() {
        let bytes = vec![0x41u8; 57];
        let wrapped = encode_lines(&bytes, 76);
        assert!(wrapped.ends_with("\r\n"));
        for line in wrapped.split("\r\n").filter(|line| !line.is_empty()) {
            assert!(line.len() <= 76, "{line}");
        }
    }
}
