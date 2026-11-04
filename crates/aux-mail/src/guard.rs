//! The per-connection read guard that bounds what an IMAP server can make us
//! buffer.
//!
//! `async-imap` sizes its receive buffer from the literal the server declares,
//! so a server that lies about `RFC822.SIZE` can hand the client a body many
//! times the configured cap. [`GuardedStream`] sits under the IMAP client,
//! counts the bytes it actually reads, and fails the read at a ceiling instead
//! of draining whatever the server sends. The wrapper lives here rather than in
//! [`crate::dial`] because the ceiling comes from
//! [`crate::limits::Limits`], not from the transport; the dialer builds it in
//! [`crate::dial::Dialer::connect_guarded`].

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Bytes the read guard lets a connection read above the message cap, for IMAP
/// framing (`SELECT`, tagged completions). Fixed and small.
pub(crate) const READ_GUARD_OVERHEAD: usize = 64 * 1024;

/// Largest slice the guard hands to one inner read.
const GUARD_SCRATCH: usize = 16 * 1024;

/// The marker a [`GuardedStream`] puts on the `io::Error` it returns once the
/// connection has read past its ceiling.
#[derive(Debug, thiserror::Error)]
#[error("IMAP read hit the {limit}-byte guard ceiling after {seen} bytes")]
pub(crate) struct ByteLimit {
    /// The ceiling the stream was armed with.
    pub(crate) limit: usize,
    /// Bytes read when the ceiling was hit.
    pub(crate) seen: usize,
}

/// A stream wrapper that refuses to read more than `limit` bytes.
///
/// `literal_limit` is the largest `{N}` declaration accepted, refused at the
/// header so `async-imap` never sizes a buffer from a hostile `N`. It defaults
/// to `limit` (the established behaviour); callers that fetch a bounded partial
/// arm it lower than the connection total.
#[derive(Debug)]
pub(crate) struct GuardedStream<S> {
    inner: S,
    limit: usize,
    literal_limit: usize,
    seen: usize,
    scratch: Box<[u8]>,
    scan: Scan,
}

impl<S> GuardedStream<S> {
    pub(crate) fn new(inner: S, limit: usize) -> Self {
        Self::with_literal_limit(inner, limit, limit)
    }

    /// The same guard with a literal declaration ceiling distinct from the
    /// total-read ceiling.
    pub(crate) fn with_literal_limit(inner: S, limit: usize, literal_limit: usize) -> Self {
        Self {
            inner,
            limit,
            literal_limit,
            seen: 0,
            scratch: vec![0u8; GUARD_SCRATCH].into_boxed_slice(),
            scan: Scan::default(),
        }
    }
}

/// How a partial `{N}` / `{N+}` literal header reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Not inside a header.
    Idle,
    /// After `{`, reading digits.
    Digits,
    /// After the digits' optional `+`.
    Plus,
    /// After `}`, expecting `\r`.
    Cr,
    /// After `\r`, expecting `\n`.
    Lf,
}

/// The literal-header scanner, carried across reads.
///
/// `async-imap` sizes its receive buffer from the literal a server declares,
/// before the guard can see the payload, so an oversized declaration must be
/// refused at the header. The scanner is a byte-at-a-time state machine with
/// no byte carry: digits accumulate with checked arithmetic (so any number of
/// leading zeros is ignored, and an overflow is oversized), and the `N` bytes
/// of an accepted header's literal body are skipped without scanning, so a
/// legitimate body containing `{999999999}\r\n` is not refused.
#[derive(Debug)]
struct Scan {
    state: State,
    value: u64,
    skip: u64,
}

impl Default for Scan {
    fn default() -> Self {
        Self {
            state: State::Idle,
            value: 0,
            skip: 0,
        }
    }
}

impl Scan {
    /// Feed one byte. Returns `Some(n)` when a complete `{n}`/`{n+}` header
    /// declares more than `ceiling`, or when the value overflows; the scanner
    /// resets either way.
    fn feed(&mut self, byte: u8, ceiling: u64) -> Option<u64> {
        if self.skip > 0 {
            // Inside an accepted literal's body: forward without scanning.
            self.skip -= 1;
            return None;
        }
        match self.state {
            State::Idle => self.restart(byte),
            State::Digits => {
                if byte.is_ascii_digit() {
                    let digit = u64::from(byte - b'0');
                    match self
                        .value
                        .checked_mul(10)
                        .and_then(|value| value.checked_add(digit))
                    {
                        Some(value) => self.value = value,
                        None => {
                            self.reset();
                            return Some(u64::MAX);
                        }
                    }
                } else if byte == b'+' {
                    self.state = State::Plus;
                } else if byte == b'}' {
                    self.state = State::Cr;
                } else {
                    self.restart(byte);
                }
            }
            State::Plus => {
                if byte == b'}' {
                    self.state = State::Cr;
                } else {
                    self.restart(byte);
                }
            }
            State::Cr => {
                if byte == b'\r' {
                    self.state = State::Lf;
                } else {
                    self.restart(byte);
                }
            }
            State::Lf => {
                if byte == b'\n' {
                    let declared = self.value;
                    self.reset();
                    if declared > ceiling {
                        return Some(declared);
                    }
                    self.skip = declared;
                } else {
                    self.restart(byte);
                }
            }
        }
        None
    }

    fn reset(&mut self) {
        self.state = State::Idle;
        self.value = 0;
    }

    /// Leave any partial header; a `{` starts a new one.
    fn restart(&mut self, byte: u8) {
        self.reset();
        if byte == b'{' {
            self.state = State::Digits;
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for GuardedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.seen >= this.limit {
            return Poll::Ready(Err(io::Error::other(ByteLimit {
                limit: this.limit,
                seen: this.seen,
            })));
        }
        let budget = (this.limit - this.seen)
            .min(this.scratch.len())
            .min(buf.remaining());
        if budget == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut scratch = ReadBuf::new(&mut this.scratch[..budget]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut scratch) {
            Poll::Ready(Ok(())) => {
                let filled = scratch.filled();
                // Refuse an oversized literal declaration *before* forwarding
                // it: otherwise async-imap sizes its buffer from the declared
                // N and allocates up to its own 512 MiB cap.
                let ceiling = u64::try_from(this.literal_limit).unwrap_or(u64::MAX);
                for &byte in filled {
                    if this.scan.feed(byte, ceiling).is_some() {
                        return Poll::Ready(Err(io::Error::other(ByteLimit {
                            limit: this.literal_limit,
                            seen: this.seen,
                        })));
                    }
                }
                this.seen += filled.len();
                buf.put_slice(filled);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for GuardedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The ceiling a failed IMAP read crossed, when the read guard caused it.
pub(crate) fn read_limit(error: &async_imap::error::Error) -> Option<(usize, usize)> {
    match error {
        async_imap::error::Error::Io(error) => error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<ByteLimit>())
            .map(|limit| (limit.limit, limit.seen)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// A reader that never ends and always fills the buffer.
    struct Endless;

    impl AsyncRead for Endless {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let fill = buf.remaining().min(1024);
            let chunk = [b'x'; 1024];
            buf.put_slice(&chunk[..fill]);
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn the_guard_stops_at_its_ceiling() {
        let ceiling = 8 * 1024;
        let mut stream = GuardedStream::new(Endless, ceiling);
        let mut buffer = [0u8; 1024];
        let mut failed = false;
        for _ in 0..64 {
            match stream.read(&mut buffer).await {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        assert!(failed, "the guard must fail the read");
        assert!(
            stream.seen <= ceiling,
            "read {} over {ceiling}",
            stream.seen
        );
    }

    /// A reader that hands out the queued chunks, one `poll_read` at a time.
    struct Chunks {
        chunks: Vec<Vec<u8>>,
    }

    impl AsyncRead for Chunks {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let remove = if let Some(chunk) = this.chunks.first_mut() {
                let take = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..take]);
                chunk.drain(..take);
                chunk.is_empty()
            } else {
                false
            };
            if remove {
                this.chunks.remove(0);
            }
            Poll::Ready(Ok(()))
        }
    }

    fn feed_all(scan: &mut Scan, bytes: &[u8], ceiling: u64) -> Option<u64> {
        bytes.iter().find_map(|&byte| scan.feed(byte, ceiling))
    }

    const CEILING: u64 = 4096;

    #[test]
    fn scanner_allows_the_ceiling_and_refuses_one_past() {
        let mut scan = Scan::default();
        assert_eq!(feed_all(&mut scan, b"{4096}\r\n", CEILING), None);

        let mut scan = Scan::default();
        assert_eq!(feed_all(&mut scan, b"{4097}\r\n", CEILING), Some(4097));

        // A header split across feeds still resolves.
        let mut scan = Scan::default();
        assert_eq!(feed_all(&mut scan, b"{40", CEILING), None);
        assert_eq!(feed_all(&mut scan, b"97}\r\n", CEILING), Some(4097));

        // The `{N+}` non-synchronising form.
        let mut scan = Scan::default();
        assert_eq!(feed_all(&mut scan, b"{9999+}\r\n", CEILING), Some(9999));

        // A brace that is not a literal header is ignored.
        let mut scan = Scan::default();
        assert_eq!(feed_all(&mut scan, b"not {a header", CEILING), None);
    }

    #[test]
    fn scanner_refuses_leading_zero_padding() {
        let mut large = vec![b'{'];
        large.extend_from_slice(&[b'0'; 40]);
        large.extend_from_slice(b"536870000}\r\n");
        let mut scan = Scan::default();
        assert!(feed_all(&mut scan, &large, CEILING).is_some());

        let mut small = vec![b'{'];
        small.extend_from_slice(&[b'0'; 40]);
        small.extend_from_slice(b"50}\r\n");
        let mut scan = Scan::default();
        assert_eq!(feed_all(&mut scan, &small, CEILING), None);
    }

    #[test]
    fn scanner_refuses_an_overflowing_value() {
        let mut scan = Scan::default();
        assert!(
            feed_all(&mut scan, b"{123456789012345678901234567890", CEILING).is_some(),
            "overflow must be refused as soon as it happens, before any closing brace"
        );
    }

    #[test]
    fn scanner_refuses_the_oversized_header_at_every_split() {
        let wire = b"* 1 FETCH (BODY[] {536870000}\r\n";
        for split in 0..=wire.len() {
            let mut scan = Scan::default();
            let mut hit = feed_all(&mut scan, &wire[..split], CEILING);
            if hit.is_none() {
                hit = feed_all(&mut scan, &wire[split..], CEILING);
            }
            assert!(hit.is_some(), "split {split} must be refused");
        }
    }

    #[tokio::test]
    async fn a_literal_body_is_skipped_and_arrives_intact() {
        let body = b"prefix {999999999}\r\n suffix";
        let mut wire = format!("* 1 FETCH (BODY[] {{{}}}\r\n", body.len()).into_bytes();
        wire.extend_from_slice(body);
        let ceiling = 4096 + 64 * 1024;
        for split in 0..=wire.len() {
            let chunks: Vec<Vec<u8>> = vec![wire[..split].to_vec(), wire[split..].to_vec()]
                .into_iter()
                .filter(|chunk| !chunk.is_empty())
                .collect();
            let mut stream = GuardedStream::new(Chunks { chunks }, ceiling);
            let mut out = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(read) => out.extend_from_slice(&buffer[..read]),
                    Err(error) => panic!("split {split} refused a valid literal: {error}"),
                }
            }
            assert_eq!(out, wire, "split {split} changed the bytes");
        }
    }
}
