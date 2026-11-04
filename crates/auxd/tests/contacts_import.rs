//! A sandboxed daemon previews, then imports, a contacts
//! file through `POST /v1/contacts/import`, and the answer carries counts and
//! column names only.
//!
//! In-process on an ephemeral loopback port and a temp home: no network, no real
//! `~/.auxesis`, no Keychain. People are fictional, phones E.164 test numbers.

mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aux_crm::Crm;
use aux_store::{NewParty, PartyKind, Store};
use auxd::api::{self, ApiHandle, ApiOptions};
use kernel_core::{config_path, store_path};
use serde_json::{json, Value};
use tempfile::tempdir;

use common::HttpResponse;

const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A HubSpot-style export: a company and an unknown column (both kept on the card), one
/// row with a national number and no country, one row with nothing that names a party,
/// and Jonas, who is already a client.
const CSV: &str = "First Name,Last Name,Email,Phone Number,Company Name,Lifecycle Stage\n\
Camille,Exemple,camille@exemple.test,+33 6 00 00 00 11,Atelier Exemple,customer\n\
Jonas,Weber,jonas@weber.test,+41 79 000 00 22,Weber AG,lead\n\
Mara,Lindqvist,mara@lindqvist.test,06 00 00 00 33,,lead\n\
,,,,,Orphan SARL\n";

/// Every value of the fixture: none may appear in an answer.
const VALUES: [&str; 11] = [
    "Camille",
    "Exemple",
    "Jonas",
    "Weber",
    "Mara",
    "Lindqvist",
    "camille@exemple.test",
    "jonas@weber.test",
    "mara@lindqvist.test",
    "+33600000011",
    "Orphan SARL",
];

struct TestApi {
    dir: tempfile::TempDir,
    home: PathBuf,
    addr: SocketAddr,
    _handle: ApiHandle,
}

impl TestApi {
    fn start() -> Self {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(config_path(&home), "version = 1\n").unwrap();
        let _ = Store::open(&store_path(&home)).unwrap();
        std::fs::write(api::token_path(&home), TEST_TOKEN).unwrap();
        let handle = api::spawn(
            &home,
            ApiOptions {
                port: 0,
                event_poll: Duration::from_millis(25),
                ..ApiOptions::default()
            },
        )
        .unwrap();
        Self {
            addr: handle.addr(),
            dir,
            home,
            _handle: handle,
        }
    }

    fn store(&self) -> Store {
        Store::open(&store_path(&self.home)).unwrap()
    }

    fn file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: &str,
    ) -> HttpResponse {
        let (addr, method, path) = (self.addr, method.to_string(), path.to_string());
        let (token, body) = (token.map(str::to_string), body.to_string());
        tokio::task::spawn_blocking(move || {
            common::http(addr, &method, &path, token.as_deref(), Some(&body))
        })
        .await
        .unwrap()
    }

    async fn import(&self, body: Value) -> HttpResponse {
        self.call(
            "POST",
            "/v1/contacts/import",
            Some(TEST_TOKEN),
            &body.to_string(),
        )
        .await
    }
}

fn assert_no_values(response: &HttpResponse) {
    for value in VALUES {
        assert!(
            !response.body.contains(value),
            "the answer carries `{value}`: {}",
            response.body
        );
    }
}

fn path_json(path: &Path) -> Value {
    json!(path.to_str().unwrap())
}

#[tokio::test]
async fn preview_changes_nothing_then_import_tags_the_clients() {
    let api = TestApi::start();
    let store = api.store();
    Crm::new(&store)
        .create(NewParty {
            kind: PartyKind::Person,
            display_name: "Jonas Weber".to_string(),
            emails: vec!["jonas@weber.test".to_string()],
            origin: "owner".to_string(),
            ..NewParty::default()
        })
        .unwrap();
    let file = api.file("hubspot.csv", CSV);
    let (contacts_before, events_before) = (
        store.contacts().unwrap().len(),
        store.event_count("contacts.imported").unwrap(),
    );

    let preview = api
        .import(json!({"path": path_json(&file), "dry_run": true, "tag": "client"}))
        .await;
    assert_eq!(preview.status, 200, "{}", preview.body);
    assert_no_values(&preview);
    let body = preview.json();
    assert_eq!(body["dry_run"], true);
    assert_eq!(body["format"], "csv");
    assert_eq!(body["contacts"], 3);
    assert_eq!(body["parties_created"], 2);
    assert_eq!(body["parties_updated"], 1);
    assert_eq!(body["conflicts"], 0);
    assert_eq!(body["skipped"]["no_name_or_contact"], 1);
    assert_eq!(body["skipped"]["phone_needs_country"], 1);
    let mapped: Vec<(&str, &str)> = body["mapped_columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["column"].as_str().unwrap(), c["as"].as_str().unwrap()))
        .collect();
    assert_eq!(
        mapped,
        [
            ("First Name", "given"),
            ("Last Name", "family"),
            ("Email", "email"),
            ("Phone Number", "phone"),
            ("Company Name", "company"),
            ("Lifecycle Stage", "note line")
        ]
    );
    assert_eq!(body["unmapped_columns"], json!([]));
    // The store is as it was: no contacts, one party, no import event.
    assert_eq!(store.contacts().unwrap().len(), contacts_before);
    assert_eq!(Crm::new(&store).list().unwrap().len(), 1);
    assert_eq!(
        store.event_count("contacts.imported").unwrap(),
        events_before
    );

    let done = api
        .import(json!({"path": path_json(&file), "dry_run": false, "tag": "client"}))
        .await;
    assert_eq!(done.status, 200, "{}", done.body);
    assert_no_values(&done);
    let done = done.json();
    // The preview predicted the import.
    assert_eq!(done["contacts"], body["contacts"]);
    assert_eq!(done["parties_created"], body["parties_created"]);
    assert_eq!(done["parties_updated"], body["parties_updated"]);
    assert_eq!(done["skipped"], body["skipped"]);
    assert_eq!(
        store.event_count("contacts.imported").unwrap(),
        events_before + 1
    );
    for payload in store.event_payloads("contacts.imported").unwrap() {
        assert!(
            !VALUES.iter().any(|value| payload.contains(value)),
            "{payload}"
        );
    }

    let list = api
        .call("GET", "/v1/clients", Some(TEST_TOKEN), "")
        .await
        .json();
    let rows = list.as_array().unwrap();
    assert_eq!(rows.len(), 3);
    for row in rows {
        assert_eq!(row["tags"], json!(["client"]), "{row}");
    }
    // The national number was not kept, and never assumed French.
    let mara = rows
        .iter()
        .find(|row| row["display_name"] == "Mara Lindqvist")
        .unwrap();
    assert_eq!(mara["phones"], json!([]));
}

#[tokio::test]
async fn vcard_preview_and_country_for_national_numbers() {
    let api = TestApi::start();
    let card = "BEGIN:VCARD\nVERSION:3.0\nFN:Camille Exemple\nTEL:06 00 00 00 11\n\
                TZ:-05:00\nEND:VCARD\n";
    let file = api.file("contacts.vcf", card);

    let bare = api
        .import(json!({"path": path_json(&file), "dry_run": true}))
        .await
        .json();
    assert_eq!(bare["format"], "vcard");
    assert_eq!(bare["contacts"], 1);
    assert_eq!(bare["phones"], 0);
    assert_eq!(bare["skipped"]["phone_needs_country"], 1);
    // A UTC offset is not an IANA zone: the preview reports it, the card gets none.
    assert_eq!(bare["skipped"]["time_zone_not_iana"], 1);
    assert!(bare.get("mapped_columns").is_none());

    let fr = api
        .import(json!({"path": path_json(&file), "dry_run": true, "country": "FR"}))
        .await
        .json();
    assert_eq!(fr["phones"], 1);
    assert_eq!(fr["skipped"]["phone_needs_country"], 0);
    let zz = api
        .import(json!({"path": path_json(&file), "dry_run": true, "country": "ZZ"}))
        .await;
    common::assert_error(&zz, 422, "contacts_import_invalid");
}

#[tokio::test]
async fn bad_requests_are_refused_and_name_no_one() {
    let api = TestApi::start();
    let file = api.file("hubspot.csv", CSV);
    let link = api.dir.path().join("link.csv");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    let junk = api.file("notes.csv", "foo,bar\n1,2\n");
    let big_dir = api.dir.path().to_path_buf();

    let refused = |body: Value| async { api.import(body).await };
    for body in [
        json!({"path": "hubspot.csv", "dry_run": true}),
        json!({"path": path_json(&link), "dry_run": true}),
        json!({"path": path_json(&big_dir), "dry_run": true}),
        json!({"path": path_json(&junk), "dry_run": true}),
        json!({"path": path_json(&file), "dry_run": true, "tag": "vip"}),
        json!({"path": path_json(&file)}),
        json!({"path": path_json(&file), "dry_run": true, "extra": 1}),
        json!({"path": "/nonexistent/export.csv", "dry_run": true}),
    ] {
        let response = refused(body.clone()).await;
        common::assert_error(&response, 422, "contacts_import_invalid");
        assert_no_values(&response);
    }
    assert_eq!(api.store().contacts().unwrap().len(), 0);

    let unauthenticated = api
        .call(
            "POST",
            "/v1/contacts/import",
            None,
            &json!({"path": path_json(&file), "dry_run": true}).to_string(),
        )
        .await;
    assert_eq!(unauthenticated.status, 401);
}
