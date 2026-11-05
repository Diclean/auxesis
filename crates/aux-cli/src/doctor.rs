//! `aux doctor` — installation health checks.
//!
//! Checks are honest by construction: the store is not just opened, its
//! schema is verified and an audit event is actually written; a read-only
//! home fails instead of pretending everything is fine. The doctor also says
//! plainly which **pieces are missing for a first run** — the assistant
//! service, at least one AI service and at least one agent — so "all checks
//! passed" is never printed on a machine where the app cannot work.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use aux_store::{Store, SCHEMA_VERSION};
use kernel_core::{auxesis_home, config_path, ensure_home, store_path, Config, Lang};

/// How long the doctor waits for the local service to accept a connection.
const SERVICE_PROBE_TIMEOUT: Duration = Duration::from_millis(400);

fn pick(fr: &'static str, en: &'static str) -> &'static str {
    pick_for(Lang::from_env(), fr, en)
}

fn pick_for(lang: Lang, fr: &'static str, en: &'static str) -> &'static str {
    match lang {
        Lang::Fr => fr,
        Lang::En => en,
    }
}

fn pick_string(fr: String, en: String) -> String {
    match Lang::from_env() {
        Lang::Fr => fr,
        Lang::En => en,
    }
}

/// One named check.
pub struct Check {
    /// Short name (`home`, `config`, `store`, `service`, `providers`, `agents`).
    pub name: &'static str,
    /// Whether the check succeeded.
    pub ok: bool,
    /// Human-readable outcome, including the next step when it failed.
    pub detail: String,
}

/// Result of a full doctor run.
pub struct Report {
    /// Checks in execution order.
    pub checks: Vec<Check>,
}

impl Report {
    /// Whether every check passed.
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|check| check.ok)
    }

    /// Print the report. Output errors (broken pipe) are ignored.
    pub fn print(&self) {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let _ = writeln!(
            out,
            "{}",
            pick(
                "aux doctor — santé d'Auxesis",
                "aux doctor — Auxesis health"
            )
        );
        for check in &self.checks {
            let mark = if check.ok { "[ok]" } else { "[fail]" };
            let _ = writeln!(out, "  {mark} {:<8} {}", check.name, clean(&check.detail));
        }
        let _ = writeln!(out, "{}", summary(self.passed()));
    }
}

fn summary(passed: bool) -> &'static str {
    if passed {
        pick("tout est en ordre", "all checks passed")
    } else {
        pick(
            "certaines vérifications ont échoué — corrige les lignes [fail] ci-dessus, puis relance `aux doctor`",
            "some checks failed — fix the [fail] lines above, then run `aux doctor` again",
        )
    }
}

/// Replace control characters so untrusted values can't forge output lines.
fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// Run every check against the resolved Auxesis home.
pub fn run() -> Report {
    let home = auxesis_home();
    let mut checks = Vec::new();

    let home_check = check_home(&home);
    let home_ok = home_check.ok;
    checks.push(home_check);
    checks.push(check_secrets(&home));

    let mut config: Option<Config> = None;
    if home_ok {
        let (check, parsed) = check_config(&home);
        checks.push(check);
        config = parsed;
    }

    if config.is_some() {
        checks.push(check_store(&home));
    }

    checks.push(check_service());
    checks.push(check_providers(&home));
    checks.push(check_agents(config.as_ref(), &home));

    Report { checks }
}

fn check_home(home: &Path) -> Check {
    let handle = match ensure_home(home) {
        Ok(handle) => handle,
        Err(err) => {
            return Check {
                name: "home",
                ok: false,
                detail: format!("{} ({err})", home.display()),
            };
        }
    };

    // Prove we can actually write: a read-only home must fail here. The probe
    // goes through the verified home handle (J-02 write gateway), never a
    // path string a swapped symlink could redirect.
    let probe = Path::new(".doctor-probe");
    match handle.write(probe, b"ok", 0o600) {
        Ok(()) => {
            let _ = handle.remove_file(probe);
            Check {
                name: "home",
                ok: true,
                detail: pick_string(
                    format!("{} (accessible en écriture)", home.display()),
                    format!("{} (writable)", home.display()),
                ),
            }
        }
        Err(err) => Check {
            name: "home",
            ok: false,
            detail: pick_string(
                format!("{} (écriture impossible : {err})", home.display()),
                format!("{} (not writable: {err})", home.display()),
            ),
        },
    }
}

/// The `.env` key store must not be readable or writable by other users.
///
/// A shared mode does not stop the daemon (a working setup keeps working),
/// but it is a security problem: the doctor reports it and names the one-line
/// fix. The file's contents are never read here, so no key can reach the
/// terminal; the once-per-process warning is emitted too when the mode is bad.
fn check_secrets(home: &Path) -> Check {
    let path = home.join(aux_providers::key::ENV_FILE);
    match aux_providers::key::env_file_mode_warning(&path) {
        Some(warning) => {
            aux_providers::key::warn_env_file_mode_once(&path);
            Check {
                name: "secrets",
                ok: false,
                detail: pick_string(
                    format!(
                        "{} est accessible aux autres utilisateurs (mode {:03o}) — lance `chmod 600 {}`",
                        warning.path.display(),
                        warning.mode,
                        warning.path.display()
                    ),
                    format!(
                        "{} is accessible to other users (mode {:03o}) — run `chmod 600 {}`",
                        warning.path.display(),
                        warning.mode,
                        warning.path.display()
                    ),
                ),
            }
        }
        None if path.exists() => Check {
            name: "secrets",
            ok: true,
            detail: pick_string(
                format!("{} n'est accessible qu'à son propriétaire", path.display()),
                format!("{} is private to its owner", path.display()),
            ),
        },
        None => Check {
            name: "secrets",
            ok: true,
            detail: pick(
                "aucun fichier .env — aucun secret au repos",
                "no .env file — no secret at rest",
            )
            .to_owned(),
        },
    }
}

fn check_config(home: &Path) -> (Check, Option<Config>) {
    // A fresh home starts with the chief, as the daemon would make it; a
    // failure here is reported by the load below.
    if let Ok(verified) = kernel_core::verified_home_or_verify(home) {
        let _ = aux_engine::config::bootstrap_config(&verified);
    }
    match aux_engine::config::load_or_create(&config_path(home)) {
        Ok(config) => {
            let agent = if config.default_agent.is_empty() {
                pick("aucun", "none").to_owned()
            } else {
                clean(&config.default_agent)
            };
            (
                Check {
                    name: "config",
                    ok: true,
                    detail: format!(
                        "version {} · {}{}",
                        config.version,
                        pick("agent par défaut : ", "default agent: "),
                        agent
                    ),
                },
                Some(config),
            )
        }
        Err(err) => (
            Check {
                name: "config",
                ok: false,
                detail: pick_string(
                    format!("{err} — corrige le fichier, puis relance `aux doctor`"),
                    format!("{err} — fix the file, then run `aux doctor` again"),
                ),
            },
            None,
        ),
    }
}

/// The local service answers on its TCP port (an `auxd` that is alive).
fn check_service() -> Check {
    let addr = match service_addr() {
        Ok(addr) => addr,
        Err(err) => {
            // H-03/J-02 port tripwire: a sandbox must not probe the real
            // daemon; report it as a failed check instead of connecting.
            return Check {
                name: "service",
                ok: false,
                detail: err,
            };
        }
    };
    match TcpStream::connect_timeout(&addr, SERVICE_PROBE_TIMEOUT) {
        Ok(_) => Check {
            name: "service",
            ok: true,
            detail: pick("le service tourne sur ce Mac", "the service is running on this Mac").to_owned(),
        },
        Err(err) => Check {
            name: "service",
            ok: false,
            detail: pick_string(
                format!(
                    "le service n'est pas joignable ({err}) — lance `aux install` (macOS) ou le bouton Démarrer de l'app"
                ),
                format!(
                    "the service is not reachable ({err}) — run `aux install` (macOS) or use the app's Start button"
                ),
            ),
        },
    }
}

/// Address the app/doctor probe, resolved by the **same** shared parser the
/// GUI client uses (J-02 round 3): `AUXESIS_API` when set (production), else
/// `AUXESIS_API_PORT` (`0` = "no endpoint"), else the local default. While
/// the sandbox guard is active, `--api`/`AUXESIS_API` are refused and the
/// real daemon port 2893 is refused (GLM P3: no second parser).
fn service_addr() -> Result<SocketAddr, String> {
    let endpoint = kernel_core::resolve_client_endpoint(&[])?;
    let Some(port) = endpoint.port else {
        return Err(format!(
            "aucun service : {}=0 / no service endpoint: {}=0",
            kernel_core::API_PORT_ENV,
            kernel_core::API_PORT_ENV
        ));
    };
    let ip: IpAddr = match endpoint.host.as_str() {
        "localhost" | "127.0.0.1" | "0.0.0.0" => IpAddr::V4(Ipv4Addr::LOCALHOST),
        "[::1]" | "::1" => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other
            .parse()
            .map_err(|_| format!("unsupported service host: {other}"))?,
    };
    Ok(SocketAddr::new(ip, port))
}

/// The AI service check reads the file the **daemon** reads.
///
/// The daemon resolves its brain chain from `providers.toml` when that file
/// exists, and falls back to the legacy `[[providers]]` table in
/// `config.toml` only when it does not. The doctor asks the same loaders, so
/// it can never report a provider the daemon would not use
/// (DOCTOR-PROVIDERS-1).
fn check_providers(home: &Path) -> Check {
    let providers_path = home.join(aux_providers::PROVIDERS_FILE);
    if auxd::brains::providers_toml_present(home) {
        providers_from_toml(home, &providers_path)
    } else {
        providers_from_legacy_config(home, &providers_path)
    }
}

/// `providers.toml`: the file the daemon reads. The loader is the daemon's
/// own (`aux_providers::load_providers_for_home`, the call `auxd::brains`
/// makes), never a copy of it.
fn providers_from_toml(home: &Path, path: &Path) -> Check {
    match aux_providers::load_providers_for_home(home) {
        Ok(file) if file.providers.is_empty() => Check {
            name: "providers",
            ok: false,
            detail: pick_string(
                format!(
                    "aucun service d'IA configuré — ajoute une entrée [[provider]] dans {}",
                    path.display()
                ),
                format!(
                    "no AI service configured — add a [[provider]] entry in {}",
                    path.display()
                ),
            ),
        },
        Ok(file) => Check {
            name: "providers",
            ok: true,
            detail: format!(
                "{} {}",
                file.providers.len(),
                pick(
                    "service(s) d'IA configuré(s) dans providers.toml",
                    "AI service(s) configured in providers.toml"
                )
            ),
        },
        Err(err) => Check {
            name: "providers",
            ok: false,
            detail: provider_file_error(&err, path, "[[provider]]"),
        },
    }
}

/// No `providers.toml`: the daemon falls back to the legacy `[[providers]]`
/// table of `config.toml`, so the doctor reads it with the same loader. The
/// line names `providers.toml` anyway: that is the file the daemon reads for
/// the brain chain.
fn providers_from_legacy_config(home: &Path, providers_path: &Path) -> Check {
    match aux_providers::load_providers(&config_path(home)) {
        Ok(providers) if providers.is_empty() => Check {
            name: "providers",
            ok: false,
            detail: no_provider_detail(providers_path),
        },
        Ok(providers) => Check {
            name: "providers",
            ok: true,
            detail: pick_string(
                format!(
                    "{} service(s) d'IA configuré(s) dans config.toml (hérité) — le démon lit providers.toml ({}) pour la chaîne de cerveau ; déplace les entrées là-bas",
                    providers.len(),
                    providers_path.display()
                ),
                format!(
                    "{} AI service(s) configured in config.toml (legacy) — the daemon reads providers.toml ({}) for the brain chain; move the entries there",
                    providers.len(),
                    providers_path.display()
                ),
            ),
        },
        Err(aux_providers::ConfigError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            Check {
                name: "providers",
                ok: false,
                detail: no_provider_detail(providers_path),
            }
        }
        Err(err) => Check {
            name: "providers",
            ok: false,
            detail: provider_file_error(&err, &config_path(home), "[[providers]]"),
        },
    }
}

/// The detail of a provider file the doctor could not use.
///
/// A `toml` parse error quotes the offending source line, so a key pasted
/// into the file (a `key = "sk-…"`, or any unknown field) would be echoed
/// to the terminal. For that error the doctor prints a fixed message: the
/// path and the line number, taken from the error's **span**, never from its
/// message. The loader's own validation messages carry no file content and
/// stay readable.
fn provider_file_error(err: &aux_providers::ConfigError, path: &Path, section: &str) -> String {
    if matches!(err, aux_providers::ConfigError::Parse(_)) {
        return match parse_error_line(err, path) {
            Some(line) => pick_string(
                format!(
                    "{} est illisible (ligne {line}) — corrige les entrées {section}, puis relance `aux doctor`",
                    path.display()
                ),
                format!(
                    "{} could not be read (line {line}) — fix the {section} entries, then run `aux doctor` again",
                    path.display()
                ),
            ),
            None => pick_string(
                format!(
                    "{} est illisible — corrige les entrées {section}, puis relance `aux doctor`",
                    path.display()
                ),
                format!(
                    "{} could not be read — fix the {section} entries, then run `aux doctor` again",
                    path.display()
                ),
            ),
        };
    }
    pick_string(
        format!(
            "{err} — corrige les entrées {section} dans {}, puis relance `aux doctor`",
            path.display()
        ),
        format!(
            "{err} — fix the {section} entries in {}, then run `aux doctor` again",
            path.display()
        ),
    )
}

/// The line of a TOML parse error, counted from the error's span.
///
/// The span is a byte range in the parsed text, so the line is the number of
/// newlines before it. The error's message is never read: it quotes the
/// offending line, and that line can hold a pasted key.
fn parse_error_line(err: &aux_providers::ConfigError, path: &Path) -> Option<usize> {
    let aux_providers::ConfigError::Parse(source) = err else {
        return None;
    };
    let span = source.span()?;
    // The same safe read as the load: a file swapped for a FIFO since is no wait.
    let text = aux_providers::config::read_existing(path).ok()?;
    let head = text.get(..span.start.min(text.len()))?;
    Some(head.matches('\n').count() + 1)
}

/// No provider anywhere: name the file the daemon reads for the brain chain,
/// so the next step is the file to write.
fn no_provider_detail(providers_path: &Path) -> String {
    pick_string(
        format!(
            "aucun service d'IA configuré — le démon lit providers.toml pour la chaîne de cerveau ; ajoute une entrée [[provider]] dans {}",
            providers_path.display()
        ),
        format!(
            "no AI service configured — the daemon reads providers.toml for the brain chain; add a [[provider]] entry in {}",
            providers_path.display()
        ),
    )
}

/// At least one agent configured (`default_agent`); creating one in the app is
/// still behind B-API-3, so the check says where the file is.
fn check_agents(config: Option<&Config>, home: &Path) -> Check {
    match config {
        Some(config) if !config.default_agent.is_empty() => Check {
            name: "agents",
            ok: true,
            detail: format!(
                "{}{}{}",
                pick("agent par défaut : ", "default agent: "),
                clean(&config.default_agent),
                legacy_default_hint(config, home)
            ),
        },
        Some(_) => Check {
            name: "agents",
            ok: false,
            detail: pick_string(
                format!(
                    "aucun agent configuré — crée-en un dans l'app (bientôt) ou renseigne default_agent dans {}",
                    config_path(home).display()
                ),
                format!(
                    "no agent configured — create one in the app (coming soon) or set default_agent in {}",
                    config_path(home).display()
                ),
            ),
        },
        None => Check {
            name: "agents",
            ok: false,
            detail: pick(
                "impossible de lire la configuration — corrige d'abord la ligne [fail] config",
                "the configuration could not be read — fix the [fail] config line first",
            )
            .to_owned(),
        },
    }
}

/// AGENT-DEFAULT-2: an older config names a bare `main` (not in the agent
/// registry), which has no mail, calendar or `delegate`. Nothing is migrated.
fn legacy_default_hint(config: &Config, home: &Path) -> &'static str {
    if config.default_agent != auxd::agent::LEGACY_DEFAULT_AGENT
        || auxd::agents::grants(home, &config.default_agent).is_ok()
    {
        return "";
    }
    pick(
        " — ton agent par défaut est 'main' ; mets default_agent = \"aux\" pour parler au chef",
        " — your default agent is 'main'; set default_agent = \"aux\" to use the chief",
    )
}

fn check_store(home: &Path) -> Check {
    let path = store_path(home);
    let store = match Store::open(&path) {
        Ok(store) => store,
        Err(err) => {
            return Check {
                name: "store",
                ok: false,
                detail: err.to_string(),
            };
        }
    };

    match store.schema_version() {
        Ok(version) if version == SCHEMA_VERSION => {}
        Ok(version) => {
            return Check {
                name: "store",
                ok: false,
                detail: pick_string(
                    format!(
                        "schéma inattendu v{version} (attendu v{SCHEMA_VERSION}) dans {}",
                        path.display()
                    ),
                    format!(
                        "unexpected schema v{version} (expected v{SCHEMA_VERSION}) at {}",
                        path.display()
                    ),
                ),
            };
        }
        Err(err) => {
            return Check {
                name: "store",
                ok: false,
                detail: pick_string(
                    format!("lecture du schéma : {err}"),
                    format!("reading schema: {err}"),
                ),
            };
        }
    }

    if let Err(err) = store.log_event("doctor", r#"{"result":"ok"}"#) {
        return Check {
            name: "store",
            ok: false,
            detail: pick_string(
                format!("écriture dans le journal impossible : {err}"),
                format!("audit write failed: {err}"),
            ),
        };
    }

    Check {
        name: "store",
        ok: true,
        detail: pick_string(
            format!("schéma v{SCHEMA_VERSION} dans {}", path.display()),
            format!("schema v{SCHEMA_VERSION} at {}", path.display()),
        ),
    }
}
