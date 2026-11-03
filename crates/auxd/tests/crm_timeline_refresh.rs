//! Integration test: `auxd::crm::run_job` (the code path of
//! `aux crm timeline refresh`) attaches one mail and one meeting to a party.

use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use aux_crm::{CalendarEvent, Crm, MailThread};
use aux_fakemail::{serve, SimConfig, StoredMail};
use aux_store::Store;
use auxd::apple_eventkit::{save_snapshot, EventItem, EventKitSnapshot};
use auxd::crm;
use kernel_core::{config_path, store_path};

fn start_mailbox(dir: &std::path::Path, mailbox: &[StoredMail]) -> (u16, std::path::PathBuf) {
    let sim_dir = dir.join("sim");
    std::fs::create_dir_all(&sim_dir).unwrap();
    std::fs::write(
        sim_dir.join("mailbox.json"),
        serde_json::to_vec(mailbox).unwrap(),
    )
    .unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let server = runtime
            .block_on(serve(SimConfig {
                dir: sim_dir.clone(),
                imap_port: 0,
                smtp_port: 0,
            }))
            .unwrap();
        tx.send((server.imap_port, server.ca_file.clone())).unwrap();
        loop {
            std::thread::park();
        }
    });
    rx.recv_timeout(Duration::from_secs(30)).unwrap()
}

#[test]
fn refresh_attaches_one_mail_and_one_meeting() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();

    let mailbox = vec![StoredMail {
        uid: 1,
        message_id: "<m1@mailsim.test>".to_string(),
        subject: "Kickoff agenda for Thursday".to_string(),
        from: "Camille Exemple <camille@exemple.test>".to_string(),
        to: vec!["Owner <owner@mailsim.test>".to_string()],
        cc: Vec::new(),
        date: "Mon, 6 Oct 2025 09:00:00 +0000".to_string(),
        body: "From: Camille\r\n\r\nbody\r\n".to_string(),
        flags: Vec::new(),
        in_reply_to: None,
        ..StoredMail::default()
    }];
    let (port, ca_file) = start_mailbox(dir.path(), &mailbox);

    let config = format!(
        "version = 1\n\n[privacy]\nmode = \"open\"\n\n\
         [connectors.mail]\n\n\
         [[connectors.mail.accounts]]\n\
         id = \"smokesim\"\n\
         email = \"owner@mailsim.test\"\n\n\
         [connectors.mail.accounts.imap]\n\
         host = \"127.0.0.1\"\n\
         port = {port}\n\
         security = \"tls\"\n\
         ca_file = \"{}\"\n",
        ca_file.display()
    );
    std::fs::write(config_path(&home), config).unwrap();
    std::fs::write(home.join(".env"), "AUX_MAIL_SMOKESIM=secret\n").unwrap();
    // create store (initialises the master key used to encrypt the snapshot)
    let store = Store::open(&store_path(&home)).unwrap();
    // party for the client
    let party = Crm::new(&store)
        .create(aux_store::NewParty {
            kind: aux_store::PartyKind::Person,
            display_name: "Camille Exemple".to_string(),
            name_variants: vec!["Camille Exemple".to_string()],
            emails: vec!["camille@exemple.test".to_string()],
            phones: Vec::new(),
            addresses: Vec::new(),
            tags: Vec::new(),
            notes: String::new(),
            time_zone: None,
            origin: "owner".to_string(),
        })
        .unwrap();
    drop(store);

    // snapshot with one meeting
    let snap = EventKitSnapshot {
        authorized: true,
        events: vec![EventItem {
            id: Some("evt-camille".to_string()),
            title: "Call with Camille".to_string(),
            start: "2025-10-05T10:00:00Z".to_string(),
            end: "2025-10-05T11:00:00Z".to_string(),
            all_day: None,
            calendar: "Work".to_string(),
            location: None,
            attendees: Some(vec!["camille@exemple.test".to_string()]),
            calendar_id: None,
            recurring: None,
        }],
        reminders: Vec::new(),
        ..Default::default()
    };
    save_snapshot(&home, &snap).unwrap();

    let store = Arc::new(Mutex::new(Store::open(&store_path(&home)).unwrap()));
    let result = crm::run_job(&home, &store);
    assert!(result.is_ok(), "refresh failed: {:?}", result);
    let summary = result.unwrap();
    assert!(summary.contains("1 mail"), "unexpected summary: {summary}");
    assert!(
        summary.contains("1 meetings"),
        "unexpected summary: {summary}"
    );

    let guard = store.lock().unwrap();
    let rows = guard.interactions_for_party(party.id).unwrap();
    assert!(rows.iter().any(|r| r.kind == "mail"), "no mail row");
    assert!(rows.iter().any(|r| r.kind == "meeting"), "no meeting row");
}

#[test]
fn refresh_skips_a_failing_item_and_attaches_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();

    let store = aux_store::Store::open(&store_path(&home)).unwrap();
    let party = Crm::new(&store)
        .create(aux_store::NewParty {
            kind: aux_store::PartyKind::Person,
            display_name: "Camille Exemple".to_string(),
            name_variants: vec!["Camille Exemple".to_string()],
            emails: vec!["camille@exemple.test".to_string()],
            phones: Vec::new(),
            addresses: Vec::new(),
            tags: Vec::new(),
            notes: String::new(),
            time_zone: None,
            origin: "owner".to_string(),
        })
        .unwrap();
    drop(party);

    // one good mail thread
    let good_thread = MailThread {
        account: "smokesim".to_string(),
        mailbox: "INBOX".to_string(),
        uid: 1,
        message_id: "<good@mailsim.test>".to_string(),
        subject: "Kickoff agenda for Thursday".to_string(),
        at: "2025-10-06T09:00:00Z".to_string(),
        owner: vec!["owner@mailsim.test".to_string()],
        from: vec!["camille@exemple.test".to_string()],
        to: vec!["owner@mailsim.test".to_string()],
        cc: Vec::new(),
        last_from: "camille@exemple.test".to_string(),
    };
    // one failing mail thread (invalid message id)
    let bad_thread = MailThread {
        message_id: String::new(),
        ..good_thread.clone()
    };

    let good_event = CalendarEvent {
        id: "evt-camille".to_string(),
        title: "Call with Camille".to_string(),
        start: "2025-10-05T10:00:00Z".to_string(),
        attendees: vec!["camille@exemple.test".to_string()],
    };

    let report =
        crm::attach(&store, &[good_thread, bad_thread], &[good_event]).expect("attach failed");
    assert_eq!(report.mail, 1, "mail: {:?}", report);
    assert_eq!(report.meetings, 1, "meetings: {:?}", report);
    assert_eq!(report.skipped, 1, "skipped: {:?}", report);
}

/// Point the `smokesim` account, INBOX and Sent allowed, at one simulator.
fn world_config(home: &std::path::Path, (port, ca): (u16, std::path::PathBuf)) {
    let config = format!(
        "version = 1\n[privacy]\nmode = \"open\"\n[connectors.mail]\n[[connectors.mail.accounts]]\n\
         id = \"smokesim\"\nemail = \"owner@mailsim.test\"\nonly_folders = [\"INBOX\", \"Sent\"]\n\
         [connectors.mail.accounts.imap]\nhost = \"127.0.0.1\"\nport = {port}\n\
         security = \"tls\"\nca_file = \"{}\"\n",
        ca.display()
    );
    std::fs::write(config_path(home), config).unwrap();
}

/// From the generator itself, per client: (threads, threads whose newest mail
/// is the owner's). A thread is an In-Reply-To chain up to its root.
fn expected(world: &[StoredMail], email: &str) -> (usize, usize) {
    let mut threads = std::collections::BTreeMap::<u32, Vec<&StoredMail>>::new();
    for mail in world {
        let mut root = mail;
        while let Some(up) = world
            .iter()
            .find(|m| Some(&m.message_id) == root.in_reply_to.as_ref())
        {
            root = up;
        }
        threads.entry(root.uid).or_default().push(mail);
    }
    let names = |m: &&StoredMail| {
        std::iter::once(&m.from)
            .chain(&m.to)
            .any(|a| a.contains(email))
    };
    let mine: Vec<_> = threads.values().filter(|t| t.iter().any(names)).collect();
    let newest_is_owner = |t: &&&Vec<&StoredMail>| t.last().unwrap().from.contains("owner@");
    (mine.len(), mine.iter().filter(newest_is_owner).count())
}

/// M3-TIMELINE-1 acceptance: the fictional world, its clients imported from a
/// vCard, one refresh: one row per thread, sent mails read from Sent. A second
/// refresh over a narrower window adds no row.
#[test]
fn the_world_gives_each_client_one_row_per_thread_with_its_direction() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let world = aux_fakemail::world_mailbox(chrono::Utc::now().timestamp());
    world_config(&home, start_mailbox(&dir.path().join("full"), &world));
    std::fs::write(home.join(".env"), "AUX_MAIL_SMOKESIM=secret\n").unwrap();
    let clients = [
        "camille@northwind",
        "lea@blueharbor",
        "owen@quaystone",
        "priya@verdant",
    ];
    let vcf = dir.path().join("clients.vcf");
    let card = |c: &&str| {
        format!("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:{c}\r\nEMAIL:{c}.example\r\nEND:VCARD\r\n")
    };
    std::fs::write(&vcf, clients.iter().map(card).collect::<String>()).unwrap();
    let store = Store::open(&store_path(&home)).unwrap();
    aux_runtime::contacts_import::import_file(&store, &vcf, None, Some("client")).unwrap();
    let store = Arc::new(Mutex::new(store));
    let rows = |client: &str| {
        let store = store.lock().unwrap();
        let parties = store.parties().unwrap();
        let party = parties
            .iter()
            .find(|p| p.emails[0].starts_with(client))
            .unwrap();
        let rows = store.interactions_for_party(party.id).unwrap();
        let mail: Vec<_> = rows.into_iter().filter(|row| row.kind == "mail").collect();
        let out = mail
            .iter()
            .filter(|row| row.direction.as_deref() == Some("out"))
            .count();
        (mail.len(), out)
    };
    crm::run_job(&home, &store).expect("first refresh");
    for client in clients {
        let (threads, out) = expected(&world, client);
        assert!(out >= 1, "{client}: the owner wrote last in some thread");
        assert_eq!(rows(client), (threads, out), "{client}: (rows, out)");
    }
    // The 44 oldest mails fall out of the window: some threads lose their first
    // mail, and Camille answers the owner's last mail. Same rows; that one row
    // turns `in`, since the newest mail sets the direction.
    let mut narrow: Vec<StoredMail> = world.iter().filter(|m| m.uid >= 45).cloned().collect();
    let answered = |m: &StoredMail| {
        narrow
            .iter()
            .any(|r| r.in_reply_to == Some(m.message_id.clone()))
    };
    let to_camille = |m: &&StoredMail| m.to.iter().any(|a| a.contains(clients[0])) && !answered(m);
    let last_out = narrow.iter().find(to_camille);
    let mut reply = last_out.expect("an owner mail to Camille").clone();
    reply.in_reply_to = Some(reply.message_id.clone());
    reply.message_id = "<world-reply@mailsim.test>".to_string();
    (reply.uid, reply.folder) = (999, None);
    reply.from = format!("{}.example", clients[0]);
    reply.date = chrono::Utc::now().to_rfc2822();
    narrow.push(reply);
    world_config(&home, start_mailbox(&dir.path().join("narrow"), &narrow));
    crm::run_job(&home, &store).expect("second refresh");
    for (index, client) in clients.into_iter().enumerate() {
        let (threads, out) = expected(&world, client);
        let flipped = usize::from(index == 0);
        assert_eq!(rows(client), (threads, out - flipped), "{client}");
    }
}
