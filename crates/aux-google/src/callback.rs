//! One-shot loopback callback listener for the installed-app flow.

use crate::{AuthError, SecretString};
use kernel_core::{Lang, Message};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::task::JoinSet;

const CALLBACK_PATH: &str = "/oauth2/callback";
const MAX_HEADER_BYTES: usize = 8192;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const RESPONSE_GRACE: Duration = Duration::from_secs(2);
const MAX_IN_FLIGHT_HANDLERS: usize = 1024;
const LISTEN_BACKLOG: u32 = 1024;

pub(crate) struct CallbackListener {
    listener: TcpListener,
    redirect_uri: String,
    port: u16,
    lang: Lang,
    #[cfg(test)]
    max_handlers: usize,
    #[cfg(test)]
    response_delay: Duration,
}

impl CallbackListener {
    pub(crate) async fn bind_for_lang(lang: Lang) -> Result<Self, AuthError> {
        let socket = TcpSocket::new_v4().map_err(|_| AuthError::Callback)?;
        socket
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .map_err(|_| AuthError::Callback)?;
        let listener = socket
            .listen(LISTEN_BACKLOG)
            .map_err(|_| AuthError::Callback)?;
        let address = listener.local_addr().map_err(|_| AuthError::Callback)?;
        if !address.ip().is_loopback() {
            return Err(AuthError::Callback);
        }
        Ok(Self {
            listener,
            redirect_uri: format!("http://127.0.0.1:{}{CALLBACK_PATH}", address.port()),
            port: address.port(),
            lang,
            #[cfg(test)]
            max_handlers: MAX_IN_FLIGHT_HANDLERS,
            #[cfg(test)]
            response_delay: Duration::ZERO,
        })
    }

    pub(crate) fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    pub(crate) async fn receive(
        self,
        expected_state: &str,
        timeout: Duration,
    ) -> Result<SecretString, AuthError> {
        let flow_deadline = tokio::time::Instant::now() + timeout;
        self.receive_until_valid(expected_state, flow_deadline)
            .await
    }

    async fn receive_until_valid(
        self,
        expected_state: &str,
        flow_deadline: tokio::time::Instant,
    ) -> Result<SecretString, AuthError> {
        let Self {
            listener,
            port,
            lang,
            #[cfg(test)]
            max_handlers,
            #[cfg(test)]
            response_delay,
            ..
        } = self;
        let max_handlers = {
            #[cfg(test)]
            {
                max_handlers
            }
            #[cfg(not(test))]
            {
                MAX_IN_FLIGHT_HANDLERS
            }
        };
        let response_delay = {
            #[cfg(test)]
            {
                response_delay
            }
            #[cfg(not(test))]
            {
                Duration::ZERO
            }
        };
        let (candidate_tx, mut candidate_rx) =
            tokio::sync::mpsc::unbounded_channel::<CallbackCandidate>();
        let mut pending: JoinSet<(u64, ConnectionOutcome)> = JoinSet::new();
        let mut active = VecDeque::new();
        let mut next_id = 0u64;
        loop {
            tokio::select! {
                biased;
                candidate = candidate_rx.recv() => {
                    if let Some(candidate) = candidate {
                        if candidate.completed_at <= flow_deadline {
                            return await_candidate_response(&mut pending, candidate).await;
                        }
                    }
                }
                joined = pending.join_next(), if !pending.is_empty() => {
                    if let Some(Ok((finished_id, _))) = joined {
                        active.retain(|handler: &ActiveHandler| handler.id != finished_id);
                    }
                }
                accepted = listener.accept(), if tokio::time::Instant::now() < flow_deadline => {
                    let (stream, peer) = accepted.map_err(|_| AuthError::Callback)?;
                    // An accept can become ready at the same time as the deadline.
                    if tokio::time::Instant::now() >= flow_deadline {
                        return Err(AuthError::Timeout);
                    }

                    if active.len() >= max_handlers {
                        // Let an already complete request announce itself before the
                        // oldest incomplete handler is evicted for memory pressure.
                        tokio::task::yield_now().await;
                        if let Ok(candidate) = candidate_rx.try_recv() {
                            if candidate.completed_at <= flow_deadline {
                                return await_candidate_response(&mut pending, candidate).await;
                            }
                        }
                        let oldest_idle = active.iter().position(|handler| {
                            !handler.received_any_bytes.load(Ordering::Relaxed)
                        });
                        if let Some(index) = oldest_idle {
                            let oldest = active
                                .remove(index)
                                .expect("the selected handler is still active");
                            oldest.abort.abort();
                        } else {
                            // Do not sacrifice an in-progress request to admit a
                            // newer connection when every handler has read bytes.
                            drop(stream);
                            continue;
                        }
                        // Reap an aborted or finished task before replacing it so
                        // handler task memory remains within the configured budget.
                        while pending.len() >= max_handlers {
                            tokio::select! {
                                biased;
                                candidate = candidate_rx.recv() => {
                                    if let Some(candidate) = candidate {
                                        if candidate.completed_at <= flow_deadline {
                                            return await_candidate_response(&mut pending, candidate).await;
                                        }
                                    }
                                }
                                joined = pending.join_next() => {
                                    if let Some(Ok((finished_id, _))) = joined {
                                        active.retain(|handler: &ActiveHandler| handler.id != finished_id);
                                    }
                                }
                                _ = tokio::time::sleep_until(flow_deadline) => {
                                    return Err(AuthError::Timeout);
                                }
                            }
                        }
                    }

                    if tokio::time::Instant::now() >= flow_deadline {
                        return Err(AuthError::Timeout);
                    }
                    let id = next_id;
                    next_id = next_id.wrapping_add(1);
                    let header_deadline = tokio::time::Instant::now() + HEADER_READ_TIMEOUT;
                    let received_any_bytes = Arc::new(AtomicBool::new(false));
                    let handler_received_any_bytes = Arc::clone(&received_any_bytes);
                    let expected_state = expected_state.to_owned();
                    let candidate_tx = candidate_tx.clone();
                    let abort = pending.spawn(async move {
                        let outcome = handle_connection(
                            stream,
                            HandlerContext {
                                id,
                                peer,
                                port,
                                lang,
                                expected_state,
                                flow_deadline,
                                header_deadline,
                                received_any_bytes: handler_received_any_bytes,
                                candidate_tx,
                                response_delay,
                            },
                        ).await;
                        (id, outcome)
                    });
                    active.push_back(ActiveHandler {
                        id,
                        abort,
                        received_any_bytes,
                    });
                }
                _ = tokio::time::sleep_until(flow_deadline) => {
                    // Complete requests are delivered before this timer branch.
                    if let Ok(candidate) = candidate_rx.try_recv() {
                        if candidate.completed_at <= flow_deadline {
                            return await_candidate_response(&mut pending, candidate).await;
                        }
                    }
                    return Err(AuthError::Timeout);
                }
            }
        }
    }
}

struct ActiveHandler {
    id: u64,
    abort: tokio::task::AbortHandle,
    received_any_bytes: Arc<AtomicBool>,
}

struct CallbackCandidate {
    id: u64,
    completed_at: tokio::time::Instant,
    result: Result<SecretString, AuthError>,
}

enum ConnectionOutcome {
    Invalid,
}

struct HandlerContext {
    id: u64,
    peer: std::net::SocketAddr,
    port: u16,
    lang: Lang,
    expected_state: String,
    flow_deadline: tokio::time::Instant,
    header_deadline: tokio::time::Instant,
    received_any_bytes: Arc<AtomicBool>,
    candidate_tx: tokio::sync::mpsc::UnboundedSender<CallbackCandidate>,
    response_delay: Duration,
}

async fn await_candidate_response(
    pending: &mut JoinSet<(u64, ConnectionOutcome)>,
    candidate: CallbackCandidate,
) -> Result<SecretString, AuthError> {
    let wait_for_writer = async {
        while let Some(joined) = pending.join_next().await {
            if let Ok((finished_id, _)) = joined {
                if finished_id == candidate.id {
                    break;
                }
            }
        }
    };
    let _ = tokio::time::timeout(RESPONSE_GRACE, wait_for_writer).await;
    candidate.result
}

async fn handle_connection(mut stream: TcpStream, context: HandlerContext) -> ConnectionOutcome {
    let HandlerContext {
        id,
        peer,
        port,
        lang,
        expected_state,
        flow_deadline,
        header_deadline,
        received_any_bytes,
        candidate_tx,
        response_delay,
    } = context;
    if peer.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) {
        write_failure(&mut stream, lang).await;
        return ConnectionOutcome::Invalid;
    }

    let header = match tokio::time::timeout_at(
        header_deadline,
        read_header(&mut stream, &received_any_bytes),
    )
    .await
    {
        Ok(Ok(header)) => header,
        Ok(Err(_)) => {
            write_failure(&mut stream, lang).await;
            return ConnectionOutcome::Invalid;
        }
        // An idle or incomplete connection owns only its handler slot until its
        // deadline. Dropping it here leaves other callbacks untouched.
        Err(_) => return ConnectionOutcome::Invalid,
    };

    let result = match validate_request(header.as_bytes(), port, &expected_state) {
        Ok(code) => Ok(SecretString::new(code)),
        Err(AuthError::ConsentRejected) => Err(AuthError::ConsentRejected),
        Err(_) => {
            write_failure(&mut stream, lang).await;
            return ConnectionOutcome::Invalid;
        }
    };
    let completed_at = tokio::time::Instant::now();
    if completed_at > flow_deadline {
        write_failure(&mut stream, lang).await;
        return ConnectionOutcome::Invalid;
    }

    let success = result.is_ok();
    if candidate_tx
        .send(CallbackCandidate {
            id,
            completed_at,
            result,
        })
        .is_err()
    {
        return ConnectionOutcome::Invalid;
    }
    if !response_delay.is_zero() {
        tokio::time::sleep(response_delay).await;
    }
    let _ = tokio::time::timeout(
        RESPONSE_WRITE_TIMEOUT,
        write_page(&mut stream, success, lang),
    )
    .await;
    ConnectionOutcome::Invalid
}

async fn write_failure(stream: &mut TcpStream, lang: Lang) {
    let _ = tokio::time::timeout(RESPONSE_WRITE_TIMEOUT, write_page(stream, false, lang)).await;
}

struct RequestHeader {
    bytes: [u8; MAX_HEADER_BYTES],
    len: usize,
}

impl RequestHeader {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

async fn read_header(
    stream: &mut TcpStream,
    received_any_bytes: &AtomicBool,
) -> std::io::Result<RequestHeader> {
    let mut bytes = [0u8; MAX_HEADER_BYTES];
    let mut len = 0;
    loop {
        let count = if len < MAX_HEADER_BYTES {
            stream.read(&mut bytes[len..len + 1]).await?
        } else {
            // Read only the single byte needed to distinguish an exactly full
            // header from one that exceeds the limit.
            let mut overflow_byte = [0u8; 1];
            let count = stream.read(&mut overflow_byte).await?;
            if count > 0 {
                received_any_bytes.store(true, Ordering::Relaxed);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "request headers too large",
                ));
            }
            count
        };
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "incomplete request",
            ));
        }
        received_any_bytes.store(true, Ordering::Relaxed);
        len += count;
        if bytes[..len].ends_with(b"\r\n\r\n") {
            return Ok(RequestHeader { bytes, len });
        }
    }
}

fn validate_request(header: &[u8], port: u16, expected_state: &str) -> Result<String, AuthError> {
    let text = std::str::from_utf8(header).map_err(|_| AuthError::Callback)?;
    let mut lines = text.split("\r\n");
    let request = lines.next().ok_or(AuthError::Callback)?;
    let mut parts = request.split(' ');
    let method = parts.next().ok_or(AuthError::Callback)?;
    let target = parts.next().ok_or(AuthError::Callback)?;
    let version = parts.next().ok_or(AuthError::Callback)?;
    if method != "GET"
        || version != "HTTP/1.1"
        || parts.next().is_some()
        || !target.starts_with('/')
    {
        return Err(AuthError::Callback);
    }

    let expected_host = format!("127.0.0.1:{port}");
    let mut host = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(AuthError::Callback);
        }
        let (name, value) = line.split_once(':').ok_or(AuthError::Callback)?;
        if name.eq_ignore_ascii_case("host") && host.replace(value.trim()).is_some() {
            return Err(AuthError::Callback);
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(AuthError::Callback);
        }
        if name.eq_ignore_ascii_case("content-length") && value.trim() != "0" {
            return Err(AuthError::Callback);
        }
    }
    if host != Some(expected_host.as_str()) {
        return Err(AuthError::Callback);
    }

    let parsed = url::Url::parse(&format!("http://{expected_host}{target}"))
        .map_err(|_| AuthError::Callback)?;
    if parsed.path() != CALLBACK_PATH || parsed.fragment().is_some() {
        return Err(AuthError::Callback);
    }
    let mut state = None;
    let mut code = None;
    let mut rejection = None;
    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "state" => {
                if state.replace(value.into_owned()).is_some() {
                    return Err(AuthError::Callback);
                }
            }
            "code" => {
                if code.replace(value.into_owned()).is_some() {
                    return Err(AuthError::Callback);
                }
            }
            "error" if rejection.is_some() => return Err(AuthError::Callback),
            "error" => rejection = Some(value.into_owned()),
            _ => {}
        }
    }
    let state = state.ok_or(AuthError::Callback)?;
    if !constant_time_eq(state.as_bytes(), expected_state.as_bytes()) {
        return Err(AuthError::Callback);
    }
    if let Some(error) = rejection {
        if error.is_empty() || code.is_some() {
            return Err(AuthError::Callback);
        }
        return Err(AuthError::ConsentRejected);
    }
    let code = code.ok_or(AuthError::Callback)?;
    if code.is_empty() || code.len() > 4096 {
        return Err(AuthError::Callback);
    }
    Ok(code)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(a ^ b);
    }
    difference == 0
}

async fn write_page(stream: &mut TcpStream, success: bool, lang: Lang) -> Result<(), AuthError> {
    let (status, page_lang, text) = if success {
        (
            "200 OK",
            lang,
            kernel_core::i18n::text(Message::OAuthSuccess, lang),
        )
    } else {
        (
            "400 Bad Request",
            lang,
            kernel_core::i18n::text(Message::OAuthFailure, lang),
        )
    };
    let body = format!("<!doctype html><html lang=\"{}\"><meta charset=\"utf-8\"><title>Google</title><p>{text}</p></html>", page_lang.code());
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|_| AuthError::Callback)?;
    stream.flush().await.map_err(|_| AuthError::Callback)
}

#[cfg(test)]
pub(crate) async fn test_listener() -> (CallbackListener, std::net::SocketAddr) {
    test_listener_with(MAX_IN_FLIGHT_HANDLERS, Duration::ZERO).await
}

#[cfg(test)]
pub(crate) async fn test_listener_with(
    max_handlers: usize,
    response_delay: Duration,
) -> (CallbackListener, std::net::SocketAddr) {
    let callback = CallbackListener::bind_for_lang(Lang::En)
        .await
        .expect("bind loopback listener");
    let callback = CallbackListener {
        max_handlers,
        response_delay,
        ..callback
    };
    let address = callback.listener.local_addr().expect("listener address");
    (callback, address)
}

#[cfg(test)]
mod proptests {
    //! Property tests for the loopback OAuth callback parser.
    //!
    //! `validate_request` is the only place the loopback listener touches
    //! bytes an internet peer chose, so it must never panic, must refuse
    //! anything it does not fully understand, and must bound the authorization
    //! code it returns.

    use super::*;
    use crate::AuthError;
    use proptest::prelude::*;

    /// Unreserved URL characters: they survive the query-string round trip
    /// unencoded, so a generated token is exactly the token the parser must
    /// return.
    fn url_safe_token() -> impl Strategy<Value = String> {
        proptest::collection::vec(
            prop_oneof![
                proptest::char::range('a', 'z'),
                proptest::char::range('A', 'Z'),
                proptest::char::range('0', '9'),
                Just('-'),
                Just('_'),
                Just('.'),
                Just('~'),
            ],
            1..64,
        )
        .prop_map(|chars| chars.into_iter().collect())
    }

    fn callback_target(state: &str, code: &str, error: Option<&str>) -> String {
        let mut target = format!("/oauth2/callback?state={state}");
        if let Some(error) = error {
            target.push_str(&format!("&error={error}"));
        } else {
            target.push_str(&format!("&code={code}"));
        }
        target
    }

    fn callback_header(port: u16, target: &str) -> Vec<u8> {
        format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").into_bytes()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Arbitrary bytes — invalid UTF-8, NULs, a megabyte of noise — must
        /// never panic. A success must respect the documented code bound and
        /// can only come from input that was valid UTF-8.
        #[test]
        fn validate_request_never_panics_on_arbitrary_bytes(
            header in proptest::collection::vec(any::<u8>(), 0..64 * 1024),
            port in any::<u16>(),
            expected_state in "[ -~]{0,64}",
        ) {
            if let Ok(code) = validate_request(&header, port, &expected_state) {
                prop_assert!(!code.is_empty());
                prop_assert!(code.len() <= 4096);
                prop_assert!(std::str::from_utf8(&header).is_ok());
            }
        }

        /// A well-formed request round-trips: the returned authorization code
        /// is exactly the one in the query string.
        #[test]
        fn valid_request_round_trips(
            port in 1u16..=u16::MAX,
            state in url_safe_token(),
            code in url_safe_token(),
        ) {
            let target = callback_target(&state, &code, None);
            let header = callback_header(port, &target);
            prop_assert_eq!(validate_request(&header, port, &state), Ok(code));
        }

        /// A denial carrying a non-empty `error` and the expected state is a
        /// clean `ConsentRejected`, never a panic or a bogus success.
        #[test]
        fn consent_rejection_is_clean(
            port in 1u16..=u16::MAX,
            state in url_safe_token(),
        ) {
            let target = callback_target(&state, "", Some("access_denied"));
            let header = callback_header(port, &target);
            prop_assert_eq!(
                validate_request(&header, port, &state),
                Err(AuthError::ConsentRejected)
            );
        }

        /// Wrong host, wrong path, missing state or a mismatched expected state
        /// are all refused instead of answered.
        #[test]
        fn invalid_shapes_are_refused(
            port in 1u16..=u16::MAX,
            state in url_safe_token(),
            code in url_safe_token(),
        ) {
            let target = callback_target(&state, &code, None);
            let wrong_host = format!(
                "GET {target} HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
            );
            prop_assert!(validate_request(wrong_host.as_bytes(), port, &state).is_err());

            let wrong_path = format!(
                "GET /not-the-callback?state={state}&code={code} HTTP/1.1\r\n\
                 Host: 127.0.0.1:{port}\r\n\r\n"
            );
            prop_assert!(validate_request(wrong_path.as_bytes(), port, &state).is_err());

            let missing_state =
                format!("GET /oauth2/callback?code={code} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
            prop_assert!(validate_request(missing_state.as_bytes(), port, &state).is_err());

            let mismatch = callback_header(port, &target);
            let mismatch_state = format!("{state}!");
            prop_assert!(validate_request(&mismatch, port, &mismatch_state).is_err());
        }

        /// `constant_time_eq` must agree with plain equality on every input.
        #[test]
        fn constant_time_eq_matches_equality(
            left in proptest::collection::vec(any::<u8>(), 0..128),
            right in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            prop_assert_eq!(constant_time_eq(&left, &right), left == right);
        }
    }

    #[test]
    fn very_long_header_is_refused_without_panic() {
        let header = vec![b'a'; 1024 * 1024];
        assert_eq!(
            validate_request(&header, 8080, "state"),
            Err(AuthError::Callback)
        );
    }
}
