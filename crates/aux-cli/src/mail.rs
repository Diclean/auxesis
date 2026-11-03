//! `aux mail` — mailbox setup and the owner's read commands (docs/mail.md §7).
//!
//! `add` runs discovery (preset → SRV → autoconfig → preset table), shows every
//! candidate, and stores the owner's choice. The password is read without echo
//! and written to `<home>/.env` under the MA1 key `AUX_MAIL_<ACCOUNT>`; the
//! account block is appended to `config.toml` with `toml_edit`, so comments and
//! every other section survive byte for byte.
//!
//! `test`, `list`, `search` and `read` use the same [`MailService`] the daemon
//! uses. Nothing here ever writes to `.env` outside `add`, and nothing prints a
//! password.

use aux_mail::config::{FolderMap, ImapSettings, MailAccount, MailConfig, SmtpSettings};
use aux_mail::discover::{self, Candidate, Discovery};
use aux_mail::{Dialer, EnvCredentials, ListQuery, MailService, SearchQuery};
use clap::{Args, Subcommand};
use kernel_broker::sanitize_external_text;
use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

#[derive(Debug, Args)]
pub struct MailArgs {
    #[command(subcommand)]
    pub action: MailAction,
}

#[derive(Debug, Subcommand)]
pub enum MailAction {
    /// Discover the server for an address, store the account and its password.
    Add(AddArgs),
    /// Connect once and print folder/unread counts.
    Test(TestArgs),
    /// List the newest messages of one folder.
    List(ListArgs),
    /// Search one folder server-side.
    Search(SearchArgs),
    /// Read one message.
    Read(ReadArgs),
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// The mailbox address (`camille@exemple.fr`).
    pub address: String,
}

#[derive(Debug, Args)]
pub struct TestArgs {
    /// Account id from `[connectors.mail.accounts]`; optional with one account.
    #[arg(long)]
    pub account: Option<String>,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    #[arg(long)]
    pub account: Option<String>,
    #[arg(long)]
    pub folder: Option<String>,
    #[arg(long, default_value_t = 20)]
    pub limit: usize,
    /// Only unread messages.
    #[arg(long)]
    pub unread: bool,
}

#[derive(Debug, Args)]
pub struct SearchArgs {
    /// The text to look for.
    pub query: String,
    #[arg(long)]
    pub account: Option<String>,
    #[arg(long)]
    pub folder: Option<String>,
    #[arg(long, default_value_t = 20)]
    pub limit: usize,
}

#[derive(Debug, Args)]
pub struct ReadArgs {
    /// IMAP UID from `aux mail list`.
    pub uid: u32,
    #[arg(long)]
    pub account: Option<String>,
    #[arg(long)]
    pub folder: Option<String>,
}

/// Run with the offline discovery probes (production).
pub fn run(args: MailArgs) -> ExitCode {
    let home = kernel_core::auxesis_home();
    run_with(&home, args, &discover::OfflineDiscovery)
}

pub fn run_with(home: &Path, args: MailArgs, probes: &dyn Discovery) -> ExitCode {
    let result = match args.action {
        MailAction::Add(args) => add(home, args, probes),
        MailAction::Test(args) => test(home, args),
        MailAction::List(args) => list(home, args),
        MailAction::Search(args) => search(home, args),
        MailAction::Read(args) => read(home, args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "aux mail: {err}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// add
// ---------------------------------------------------------------------------

fn add(home: &Path, args: AddArgs, probes: &dyn Discovery) -> Result<(), String> {
    let address = args.address.trim();
    let domain = discover::address_domain(address)
        .ok_or_else(|| format!("`{address}` is not an e-mail address"))?;
    let candidates = discover::discover(&domain, probes);
    if candidates.is_empty() {
        return Err(format!("no mail server could be found for {domain}"));
    }
    println!("Candidates for {address}:");
    for (index, candidate) in candidates.iter().enumerate() {
        print_candidate(index + 1, candidate);
    }
    print!("Pick a server [1-{}]: ", candidates.len());
    std::io::stdout().flush().map_err(|err| err.to_string())?;
    let choice = read_line()?
        .trim()
        .parse::<usize>()
        .map_err(|_| "enter the number of a candidate".to_string())?;
    let candidate = candidates
        .get(choice.wrapping_sub(1))
        .ok_or_else(|| format!("{choice} is not one of the candidates"))?;

    let account = account_from(address, candidate);
    let password = read_password()?;
    if password.is_empty() {
        return Err("no password given".to_string());
    }
    set_mail_secret(home, &account.id, &password)?;
    upsert_account_config(home, &account)?;
    println!(
        "Stored account `{}` ({}) and its password in {}/.env.",
        account.id,
        candidate.imap.host,
        home.display()
    );
    Ok(())
}

fn print_candidate(index: usize, candidate: &Candidate) {
    let smtp = candidate
        .smtp
        .as_ref()
        .map(|endpoint| {
            format!(
                "{}:{} ({})",
                endpoint.host,
                endpoint.port,
                endpoint.security.as_str()
            )
        })
        .unwrap_or_else(|| "no outgoing server".to_string());
    println!(
        "  {index}. [{}] {}:{} ({}) -> {smtp} — {}",
        candidate.source,
        candidate.imap.host,
        candidate.imap.port,
        candidate.imap.security.as_str(),
        kernel_broker::sanitize_external_text(&candidate.note, 200),
    );
}

fn account_from(address: &str, candidate: &Candidate) -> MailAccount {
    MailAccount {
        id: account_id(address),
        email: address.to_string(),
        display: None,
        imap: ImapSettings {
            host: candidate.imap.host.clone(),
            port: candidate.imap.port,
            security: candidate.imap.security,
            username: None,
            ca_file: None,
        },
        smtp: candidate.smtp.as_ref().map(|endpoint| SmtpSettings {
            host: endpoint.host.clone(),
            port: endpoint.port,
            security: endpoint.security,
            username: None,
            ca_file: None,
        }),
        folders: FolderMap::default(),
        only_folders: vec!["INBOX".to_string()],
    }
}

/// A stable account id from the address's local part (`[a-z0-9]`, ≤ 32).
pub fn account_id(address: &str) -> String {
    let local = address.split('@').next().unwrap_or("mail");
    let id: String = local
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(32)
        .collect::<String>()
        .to_ascii_lowercase();
    if id.is_empty() {
        "mail".to_string()
    } else {
        id
    }
}

/// Read one line from stdin, for a choice or a piped test secret.
fn read_line() -> Result<String, String> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|err| format!("reading stdin: {err}"))?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Read a password without echoing it when stdin is a terminal.
fn read_password() -> Result<String, String> {
    if !std::io::stdin().is_terminal() {
        return read_line();
    }
    print!("Password (not echoed): ");
    std::io::stdout().flush().map_err(|err| err.to_string())?;
    let _ = std::process::Command::new("stty").arg("-echo").status();
    let result = read_line();
    let _ = std::process::Command::new("stty").arg("echo").status();
    println!();
    result
}

/// Upsert `AUX_MAIL_<ACCOUNT>=value` in `<home>/.env` (0600), atomically.
fn set_mail_secret(home: &Path, account: &str, value: &str) -> Result<(), String> {
    if value.chars().any(char::is_control) {
        return Err("the password contains a control character".to_string());
    }
    let name = aux_mail::config::env_var_name(account);
    kernel_core::with_config_lock(home, || {
        let path = home.join(".env");
        let mut lines: Vec<String> = match std::fs::read_to_string(&path) {
            Ok(text) => text.lines().map(str::to_string).collect(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(err) => return Err(format!("reading {}: {err}", path.display())),
        };
        let prefix = format!("{name}=");
        lines.retain(|line| !line.trim_start().starts_with(&prefix));
        lines.push(format!("{name}={value}"));
        let mut text = lines.join("\n");
        text.push('\n');
        let handle = kernel_core::SandboxHome::open(home)
            .map_err(|err| format!("opening {}: {err}", home.display()))?;
        handle
            .write_atomic(Path::new(".env"), text.as_bytes(), 0o600)
            .map_err(|err| format!("writing {}: {err}", path.display()))
    })
    .map_err(|err| format!("acquiring the configuration lock: {err}"))?
}

/// Append (or replace) one account in `[connectors.mail.accounts]`, preserving
/// every other byte of `config.toml`.
fn upsert_account_config(home: &Path, account: &MailAccount) -> Result<(), String> {
    let path = kernel_core::config_path(home);
    let replaced = kernel_core::with_config_lock(home, || -> Result<bool, String> {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let mut document: toml_edit::DocumentMut =
            text.parse().map_err(|err: toml_edit::TomlError| {
                let at = kernel_core::describe_toml_error("", &text, err.span(), err.message());
                format!("parsing {}: {at}", path.display())
            })?;
        let account_toml = toml::to_string(account).map_err(|err| err.to_string())?;
        let table: toml_edit::Table = account_toml
            .parse::<toml_edit::DocumentMut>()
            .map_err(|err| format!("serializing the account: {err}"))?
            .as_table()
            .clone();
        let connectors = document
            .as_table_mut()
            .entry("connectors")
            .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
        let mail = connectors
            .as_table_mut()
            .ok_or("`connectors` is not a table")?
            .entry("mail")
            .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
        let accounts = mail
            .as_table_mut()
            .ok_or("`connectors.mail` is not a table")?
            .entry("accounts")
            .or_insert(toml_edit::Item::ArrayOfTables(
                toml_edit::ArrayOfTables::new(),
            ));
        let accounts = accounts
            .as_array_of_tables_mut()
            .ok_or("`connectors.mail.accounts` is not an array of tables")?;
        let index = accounts.iter().position(|entry| {
            entry.get("id").and_then(|value| value.as_str()) == Some(account.id.as_str())
        });
        let replaced = if let Some(index) = index {
            accounts.replace(index, table);
            true
        } else {
            accounts.push(table);
            false
        };
        let handle = kernel_core::SandboxHome::open(home)
            .map_err(|err| format!("opening {}: {err}", home.display()))?;
        handle
            .write_atomic(
                Path::new("config.toml"),
                document.to_string().as_bytes(),
                0o600,
            )
            .map_err(|err| format!("writing {}: {err}", path.display()))?;
        Ok(replaced)
    })
    .map_err(|err| format!("acquiring the configuration lock: {err}"))??;
    if replaced {
        println!("Updated account `{}` in config.toml.", account.id);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// test / list / search / read
// ---------------------------------------------------------------------------

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("starting the runtime: {err}"))
}

/// Read `[connectors.mail]` from `home`, or `None` when it is absent.
fn load_config(home: &Path) -> Result<MailConfig, String> {
    let text = std::fs::read_to_string(kernel_core::config_path(home))
        .map_err(|err| format!("reading config.toml: {err}"))?;
    let value: toml::Value = toml::from_str(&text).map_err(|err| {
        let err = kernel_core::redact_toml_error(&err, "config.toml", &text);
        format!("parsing {}", err.message())
    })?;
    let mail = value
        .get("connectors")
        .and_then(|connectors| connectors.get("mail"))
        .ok_or_else(|| "no `[connectors.mail]` in config.toml; run `aux mail add`".to_string())?;
    let table = toml::to_string(mail).map_err(|err| err.to_string())?;
    // No error text from the table is ever shown: serde quotes unknown
    // fields and values, and the loader's account checks quote ids.
    MailConfig::from_toml(&table).map_err(|err| {
        if err.message().starts_with("[[accounts]]") {
            "parsing [connectors.mail]: account ids must be distinct lowercase slugs, each with \
             its own secret key / identifiants de compte invalides ou en double"
                .to_string()
        } else {
            let at = kernel_core::redact_toml_error(&err, "", &table);
            format!("parsing [connectors.mail]: {}", at.message())
        }
    })
}

/// Resolve the account by `--account`, or the only configured one.
fn resolve_account<'a>(
    config: &'a MailConfig,
    wanted: Option<&str>,
) -> Result<&'a MailAccount, String> {
    match wanted {
        Some(id) => config
            .account(id)
            .ok_or_else(|| format!("unknown mail account `{id}`")),
        None => match config.accounts.as_slice() {
            [only] => Ok(only),
            [] => Err("no mail account is configured; run `aux mail add`".to_string()),
            _ => Err("several accounts are configured; pass --account".to_string()),
        },
    }
}

/// The configured mail service, or `None` when this home has no mailbox:
/// `aux skill run` reads mail through it for `docs.ingest` (M5-3).
pub(crate) fn configured_service(home: &Path) -> Option<MailService> {
    let config = load_config(home).ok()?;
    (!config.accounts.is_empty()).then(|| service(home, &config))
}

fn service(home: &Path, config: &MailConfig) -> MailService {
    let limits = config.limits.limits();
    let dialer = Dialer::new(limits.connect_timeout);
    MailService::new(
        dialer,
        limits,
        config.accounts.clone(),
        Arc::new(EnvCredentials::new(home.to_path_buf())),
    )
}

fn test(home: &Path, args: TestArgs) -> Result<(), String> {
    let config = load_config(home)?;
    let account = resolve_account(&config, args.account.as_deref())?.clone();
    let service = service(home, &config);
    let runtime = runtime()?;
    let folders = runtime
        .block_on(service.folders(&account.id))
        .map_err(|err| err.to_string())?;
    let unread = runtime
        .block_on(service.list(
            &account.id,
            &ListQuery {
                unread: Some(true),
                ..ListQuery::default()
            },
        ))
        .map_err(|err| err.to_string())?;
    println!(
        "Connected. {} folders, {} unread in INBOX.",
        folders.len(),
        unread.len()
    );
    Ok(())
}

fn list(home: &Path, args: ListArgs) -> Result<(), String> {
    let config = load_config(home)?;
    let account = resolve_account(&config, args.account.as_deref())?.clone();
    let service = service(home, &config);
    let runtime = runtime()?;
    let items = runtime
        .block_on(service.list(
            &account.id,
            &ListQuery {
                folder: args.folder,
                limit: args.limit,
                unread: args.unread.then_some(true),
                days: None,
            },
        ))
        .map_err(|err| err.to_string())?;
    print_envelopes(&items);
    Ok(())
}

fn search(home: &Path, args: SearchArgs) -> Result<(), String> {
    let config = load_config(home)?;
    let account = resolve_account(&config, args.account.as_deref())?.clone();
    let service = service(home, &config);
    let runtime = runtime()?;
    let items = runtime
        .block_on(service.search(
            &account.id,
            &SearchQuery {
                query: args.query,
                folder: args.folder,
                limit: args.limit,
                days: None,
            },
        ))
        .map_err(|err| err.to_string())?;
    print_envelopes(&items);
    Ok(())
}

fn print_envelopes(items: &[aux_mail::EnvelopeItem]) {
    println!("UID\tDATE\tFROM\tSUBJECT");
    for item in items {
        println!(
            "{}\t{}\t{}\t{}",
            item.uid,
            header(&item.date),
            header(&item.from),
            header(&item.subject),
        );
    }
}

fn header(value: &str) -> String {
    sanitize_external_text(&kernel_core::text::sanitize_text(value), 200)
}

fn read(home: &Path, args: ReadArgs) -> Result<(), String> {
    let config = load_config(home)?;
    let account = resolve_account(&config, args.account.as_deref())?.clone();
    let service = service(home, &config);
    let folder = args.folder.unwrap_or_else(|| account.folders.inbox.clone());
    let runtime = runtime()?;
    let raw = runtime
        .block_on(service.read(&account.id, args.uid, &folder, 0))
        .map_err(|err| err.to_string())?;
    let item = aux_mail::parse_message(&raw).map_err(|err| err.to_string())?;
    println!("From: {}", header(&item.from));
    println!("Subject: {}", header(&item.subject));
    println!("Date: {}", header(&item.date));
    println!();
    println!("{}", item.text);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aux_mail::config::Security;

    #[test]
    fn a_mail_config_error_never_quotes_the_file() {
        // CONFIG-ERR-ECHO-1 round 1: a key typed as a field name, a bad
        // value, and an id the account check would have quoted.
        for account in [
            "id = \"owner\"\nsk-abc = 1\n",
            "id = \"owner\"\nsecurity = \"sk-abc\"\n",
            "id = \"Sk-abc\"\n",
        ] {
            let home = tempfile::tempdir().unwrap();
            let text = format!("[[connectors.mail.accounts]]\n{account}");
            std::fs::write(kernel_core::config_path(home.path()), text).unwrap();
            let err = load_config(home.path()).unwrap_err();
            assert!(!err.contains("abc"), "{err}");
            assert!(err.starts_with("parsing [connectors.mail]: "), "{err}");
        }
    }

    struct FakeProbes;

    impl Discovery for FakeProbes {
        fn srv(&self, _domain: &str) -> Result<Vec<Candidate>, aux_mail::MailError> {
            Ok(vec![Candidate {
                source: "srv",
                note: "_imaps._tcp".to_string(),
                imap: aux_mail::Endpoint {
                    host: "imap.exemple.fr".to_string(),
                    port: 993,
                    security: Security::Tls,
                },
                smtp: None,
                username_is_full_address: true,
            }])
        }
        fn autoconfig(&self, _domain: &str) -> Result<Option<Candidate>, aux_mail::MailError> {
            Ok(None)
        }
    }

    #[test]
    fn account_ids_are_stable_and_filesystem_safe() {
        assert_eq!(account_id("Camille.Exemple@exemple.fr"), "camilleexemple");
        assert_eq!(account_id("@exemple.fr"), "mail");
        assert_eq!(
            aux_mail::config::env_var_name("camille"),
            "AUX_MAIL_CAMILLE"
        );
    }

    #[test]
    fn adding_an_account_writes_the_env_key_and_appends_the_config() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let candidate = Candidate {
            source: "srv",
            note: "_imaps._tcp".to_string(),
            imap: aux_mail::Endpoint {
                host: "imap.exemple.fr".to_string(),
                port: 993,
                security: Security::Tls,
            },
            smtp: None,
            username_is_full_address: true,
        };
        let account = account_from("camille@exemple.fr", &candidate);
        set_mail_secret(home, &account.id, "hunter2").unwrap();
        upsert_account_config(home, &account).unwrap();

        let env = std::fs::read_to_string(home.join(".env")).unwrap();
        assert!(env.contains("AUX_MAIL_CAMILLE=hunter2"), "{env}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(home.join(".env"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let text = std::fs::read_to_string(kernel_core::config_path(home)).unwrap();
        assert!(text.contains("[connectors.mail.accounts]"), "{text}");
        assert!(text.contains("host = \"imap.exemple.fr\""), "{text}");
        // A second call replaces, never duplicates.
        upsert_account_config(home, &account).unwrap();
        let text = std::fs::read_to_string(kernel_core::config_path(home)).unwrap();
        assert_eq!(text.matches("imap.exemple.fr").count(), 1, "{text}");
    }

    #[test]
    fn discovery_lists_candidates_without_network() {
        let candidates = discover::discover("exemple.fr", &FakeProbes);
        assert!(candidates.iter().any(|candidate| candidate.source == "srv"));
    }
}
