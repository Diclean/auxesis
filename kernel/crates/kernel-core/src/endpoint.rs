//! One client endpoint resolver shared by `auxesis` and `aux doctor` (J-02
//! round 3).
//!
//! Under an active sandbox guard clients take their endpoint **only** from
//! `AUXESIS_API_PORT`: `--api` and `AUXESIS_API` are refused (they can hide
//! 2893 behind query/fragment/userinfo or an odd IP spelling), and an unset
//! port is refused rather than defaulting to the real daemon. Port `0` is the
//! explicit "no endpoint" convention. Outside a sandbox the URL is parsed
//! with the same WHATWG parser the HTTP client uses (`url`), which
//! normalises decimal/hex/octal IPv4 spellings.

use crate::{sandbox_guard_active, REAL_DAEMON_PORT};

/// Environment override for the client port (`0` = no endpoint).
pub const API_PORT_ENV: &str = "AUXESIS_API_PORT";

/// A resolved client endpoint. An empty `url` and `port == None` mean "no
/// endpoint": the client must not connect anywhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientEndpoint {
    /// Normalised base URL (`""` = no endpoint).
    pub url: String,
    /// Host as the WHATWG parser resolved it (`""` = no endpoint).
    pub host: String,
    /// Port to connect to (`None` = no endpoint).
    pub port: Option<u16>,
}

impl ClientEndpoint {
    /// The explicit "no endpoint" endpoint (`AUXESIS_API_PORT=0`).
    pub fn none() -> Self {
        Self {
            url: String::new(),
            host: String::new(),
            port: None,
        }
    }

    /// Whether this endpoint points anywhere.
    pub fn has_endpoint(&self) -> bool {
        self.port.is_some()
    }
}

/// Resolve the endpoint from `args` (`--api URL` / `--api=URL`), the
/// `AUXESIS_API` environment variable and `AUXESIS_API_PORT`, honouring the
/// sandbox rules.
pub fn resolve_client_endpoint(args: &[String]) -> Result<ClientEndpoint, String> {
    resolve_from(
        args,
        std::env::var("AUXESIS_API").ok().as_deref(),
        std::env::var(API_PORT_ENV).ok().as_deref(),
        sandbox_guard_active(),
    )
}

fn resolve_from(
    args: &[String],
    api_env: Option<&str>,
    port_env: Option<&str>,
    guard_active: bool,
) -> Result<ClientEndpoint, String> {
    let api_flags = collect_api_flags(args)?;
    if guard_active {
        if !api_flags.is_empty() || api_env.is_some() {
            return Err(format!(
                "refus de sandbox : `--api`/`AUXESIS_API` est refusé sous garde — utilisez `{API_PORT_ENV}=0` (aucun service) ou un port loopback explicite. \
                 / sandbox refused: `--api`/`AUXESIS_API` is refused while the guard is active — use `{API_PORT_ENV}=0` (no service) or an explicit loopback port."
            ));
        }
        return match port_env {
            None => Err(format!(
                "refus de sandbox : {API_PORT_ENV} est requis sous garde (0 = aucun service). \
                 / sandbox refused: {API_PORT_ENV} is required while the guard is active (0 = no service)."
            )),
            Some(raw) => match raw.trim().parse::<u16>() {
                Ok(0) => Ok(ClientEndpoint::none()),
                Ok(port) if port == REAL_DAEMON_PORT => Err(crate::paths::port_refusal()),
                Ok(port) => Ok(loopback(port)),
                Err(_) => Err(format!("invalid {API_PORT_ENV}: {raw}")),
            },
        };
    }

    // Production: `--api` > `AUXESIS_API` > `AUXESIS_API_PORT` > default.
    if let Some(raw) = api_flags.first() {
        return parse_url(raw);
    }
    if let Some(raw) = api_env {
        return parse_url(raw);
    }
    if let Some(raw) = port_env {
        return match raw.trim().parse::<u16>() {
            Ok(0) => Ok(ClientEndpoint::none()),
            Ok(port) => Ok(loopback(port)),
            Err(_) => Err(format!("invalid {API_PORT_ENV}: {raw}")),
        };
    }
    Ok(loopback(REAL_DAEMON_PORT))
}

fn loopback(port: u16) -> ClientEndpoint {
    ClientEndpoint {
        url: format!("http://127.0.0.1:{port}"),
        host: "127.0.0.1".to_string(),
        port: Some(port),
    }
}

fn collect_api_flags(args: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if arg == "--api" {
            let value = it.next().ok_or_else(|| "--api needs a URL".to_string())?;
            out.push(value.clone());
        } else if let Some(value) = arg.strip_prefix("--api=") {
            out.push(value.to_string());
        }
    }
    if out.len() > 1 {
        return Err(format!(
            "multiple --api flags are refused (got {})",
            out.len()
        ));
    }
    Ok(out)
}

/// Parse a client URL with the same WHATWG parser the HTTP client uses;
/// refuse query, fragment, userinfo, non-http(s) schemes and a missing port.
/// IPv4 spellings (`0x7f000001`, `2130706433`, `0177.0.0.1`) are normalised
/// by the parser, so a `2893` hidden behind one cannot slip past the guard.
fn parse_url(raw: &str) -> Result<ClientEndpoint, String> {
    let url = url::Url::parse(raw.trim())
        .map_err(|err| format!("invalid endpoint URL {raw:?}: {err}"))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(format!("unsupported endpoint scheme {:?}", url.scheme()));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(format!(
            "endpoint URL must not carry a query or fragment: {raw}"
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("endpoint URL must not carry credentials: {raw}"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| format!("endpoint URL has no host: {raw}"))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| format!("endpoint URL has no port: {raw}"))?;
    Ok(ClientEndpoint {
        url: url.as_str().trim_end_matches('/').to_string(),
        host,
        port: Some(port),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_precedence_and_defaults() {
        let none = resolve_from(&[], None, Some("0"), false).unwrap();
        assert_eq!(none, ClientEndpoint::none());
        assert!(!none.has_endpoint());

        let port = resolve_from(&[], None, Some("4123"), false).unwrap();
        assert_eq!(port.url, "http://127.0.0.1:4123");
        assert_eq!(port.port, Some(4123));

        let default = resolve_from(&[], None, None, false).unwrap();
        assert_eq!(default.url, "http://127.0.0.1:2893");
        assert_eq!(default.port, Some(2893));

        let api = resolve_from(&[], Some("http://127.0.0.1:9999/"), None, false).unwrap();
        assert_eq!(api.url, "http://127.0.0.1:9999");

        let args = vec!["--api".to_string(), "http://127.0.0.1:9998".to_string()];
        let flag = resolve_from(&args, Some("http://127.0.0.1:9999"), Some("0"), false).unwrap();
        assert_eq!(flag.url, "http://127.0.0.1:9998");
    }

    /// Security review J02-2-BI2-02: query/fragment/userinfo must not hide a port.
    #[test]
    fn odd_url_forms_are_refused() {
        for raw in [
            "http://127.0.0.1:2893?x",
            "http://127.0.0.1:2893#f",
            "http://[::1]:2893?q=1",
            "http://user:pw@127.0.0.1:2893",
            "ftp://127.0.0.1:2893",
            "not a url",
        ] {
            assert!(
                parse_url(raw).is_err(),
                "{raw} must be refused by the endpoint parser"
            );
        }
    }

    /// The WHATWG parser normalises every IPv4 spelling, so the guard's port
    /// comparison sees the real host and port.
    #[test]
    fn ipv4_spellings_normalise_to_loopback_2893() {
        for raw in [
            "http://127.0.0.1:2893",
            "http://0x7f000001:2893",
            "http://2130706433:2893",
            "http://0177.0.0.1:2893",
            "http://localhost:2893",
            "http://[::1]:2893",
        ] {
            let endpoint = parse_url(raw).unwrap_or_else(|err| panic!("{raw}: {err}"));
            assert_eq!(endpoint.port, Some(2893), "{raw}");
            assert!(
                matches!(endpoint.host.as_str(), "127.0.0.1" | "localhost" | "[::1]"),
                "{raw} resolved to {}",
                endpoint.host
            );
        }
    }

    /// Multiple `--api` flags are refused outright.
    #[test]
    fn multiple_api_flags_are_refused() {
        let args = vec![
            "--api".to_string(),
            "http://127.0.0.1:9999".to_string(),
            "--api=http://127.0.0.1:9998".to_string(),
        ];
        let err = resolve_from(&args, None, None, false).unwrap_err();
        assert!(err.contains("multiple --api"), "{err}");
    }

    /// Under an active guard, only `AUXESIS_API_PORT` is trusted.
    #[test]
    fn active_guard_takes_the_port_only_from_the_env() {
        let args = vec!["--api".to_string(), "http://127.0.0.1:9999".to_string()];
        assert!(resolve_from(&args, None, Some("0"), true).is_err());
        assert!(resolve_from(&[], Some("http://127.0.0.1:9999"), Some("0"), true).is_err());
        assert!(resolve_from(&[], None, None, true).is_err());
        assert_eq!(
            resolve_from(&[], None, Some("0"), true).unwrap(),
            ClientEndpoint::none()
        );
        assert_eq!(
            resolve_from(&[], None, Some("4123"), true).unwrap().url,
            "http://127.0.0.1:4123"
        );
        let refused = resolve_from(&[], None, Some("2893"), true).unwrap_err();
        assert!(refused.contains("2893"), "{refused}");
    }
}
