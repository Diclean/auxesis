//! Byte-level helpers the fake-driving tests use.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Write one CRLF-terminated command line.
pub async fn send_line(stream: &mut TcpStream, line: &str) {
    stream
        .write_all(format!("{line}\r\n").as_bytes())
        .await
        .expect("write command");
    stream.flush().await.expect("flush command");
}

/// Read one CRLF-terminated line, without its terminator.
pub async fn read_line(stream: &mut TcpStream) -> String {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte).await.expect("read line");
        if read == 0 {
            break;
        }
        if byte[0] == b'\n' {
            if buffer.last() == Some(&b'\r') {
                buffer.pop();
            }
            break;
        }
        buffer.push(byte[0]);
    }
    String::from_utf8_lossy(&buffer).into_owned()
}

/// Read bytes until the buffer ends with `needle`, and return everything read.
pub async fn read_until(stream: &mut TcpStream, needle: &str) -> String {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte).await.expect("read response");
        assert_ne!(
            read,
            0,
            "server closed while waiting for {needle:?}: {}",
            String::from_utf8_lossy(&buffer)
        );
        buffer.push(byte[0]);
        if buffer.ends_with(needle.as_bytes()) {
            return String::from_utf8_lossy(&buffer).into_owned();
        }
        assert!(
            buffer.len() < 4 * 1024 * 1024,
            "response grew without {needle:?}"
        );
    }
}

/// Read a full IMAP response: everything through the line tagged `<tag>`.
pub async fn read_until_tag(stream: &mut TcpStream, tag: &str) -> String {
    let mut buffer = Vec::new();
    let mut line_start = 0;
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte).await.expect("read response");
        assert_ne!(
            read,
            0,
            "server closed before the {tag} completion: {}",
            String::from_utf8_lossy(&buffer)
        );
        buffer.push(byte[0]);
        if byte[0] == b'\n' {
            let line = String::from_utf8_lossy(&buffer[line_start..]);
            let line = line.trim_end_matches(['\r', '\n']);
            if line.starts_with(tag) && line.as_bytes().get(tag.len()) == Some(&b' ') {
                return String::from_utf8_lossy(&buffer).into_owned();
            }
            line_start = buffer.len();
        }
        assert!(buffer.len() < 4 * 1024 * 1024, "response too large");
    }
}
