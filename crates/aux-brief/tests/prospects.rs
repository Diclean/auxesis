//! Possible new clients are spotted locally, only suggested
//! (never created), and the notification carries a count and no name.

use aux_brief::{
    classify, run_once, BriefSource, BriefSourceError, CalendarItem, Inbound, MailHeader, Prospect,
    Reason, WeatherSummary,
};
use aux_notify::FakeNotifier;
use aux_store::{NewParty, Store};
use chrono::{DateTime, Local, TimeZone};
use kernel_core::Config;
use tempfile::tempdir;

const ADDRESS: &str = "mira.fictive@example.invalid";
const OWNER: &str = "owner@example.invalid";

fn raw(extra: &str) -> Vec<u8> {
    format!("From: Mira Fictive <{ADDRESS}>\r\n{extra}\r\nBody\r\n").into_bytes()
}

fn hit(subject: &str, body: &str, extra: &str) -> Option<Prospect> {
    let raw = raw(extra);
    let mail = Inbound {
        account: "fictif",
        from: &format!("Mira Fictive <{ADDRESS}>"),
        subject,
        body,
        date: "Wed, 14 Oct 2026 09:00:00 +0000",
        raw: &raw,
    };
    classify(&mail, &[OWNER.to_string()])
}

#[test]
fn classifier_gives_a_reason_code_and_skips_automated_mail() {
    let quote = hit("Logo", "Hi, could you send me a quote for a logo?", "").unwrap();
    assert_eq!(
        (quote.reason, quote.email.as_str()),
        (Reason::Quote, ADDRESS)
    );
    let referral = hit("Hello", "Anna Smit recommended you.", "").unwrap();
    assert_eq!(referral.reason, Reason::Referral);
    let slot = hit("Hello", "Are you available in March?", "").unwrap();
    assert_eq!(slot.reason, Reason::Availability);

    assert!(hit("Hello", "Nice weather.", "").is_none());
    assert!(hit(
        "Sale",
        "Book now!",
        "List-Unsubscribe: <mailto:u@example.invalid>"
    )
    .is_none());
    assert!(hit(
        "Re: quote",
        "Quote attached",
        "Auto-Submitted: auto-replied"
    )
    .is_none());
    let mail = Inbound {
        account: "fictif",
        from: "Shop <no-reply@example.invalid>",
        subject: "Your quote",
        body: "",
        date: "",
        raw: b"",
    };
    assert!(classify(&mail, &[]).is_none());
    let own = Inbound {
        from: OWNER,
        ..mail
    };
    assert!(classify(&own, &[OWNER.to_string()]).is_none());
}

struct Leads(Vec<Prospect>);

impl BriefSource for Leads {
    fn calendar_today(&self, _: &str) -> Result<Vec<CalendarItem>, BriefSourceError> {
        Ok(Vec::new())
    }
    fn weather(&self, _: &str, _: &str, _: &str) -> Result<WeatherSummary, BriefSourceError> {
        Err(BriefSourceError::Unavailable)
    }
    fn mail_headers(&self, _: &str) -> Result<Vec<MailHeader>, BriefSourceError> {
        Ok(Vec::new())
    }
    fn possible_clients(&self, _: &str) -> Result<Vec<Prospect>, BriefSourceError> {
        Ok(self.0.clone())
    }
}

fn at(day: u32) -> DateTime<Local> {
    Local
        .with_ymd_and_hms(2026, 10, day, 12, 0, 0)
        .single()
        .unwrap()
}

fn brief(store: &Store, day: u32) -> (String, String) {
    let lead = hit("Logo", "Please send a quote.", "").unwrap();
    let notifier = FakeNotifier::new();
    run_once(
        store,
        &Leads(vec![lead]),
        &notifier,
        &Config::default(),
        at(day),
        3,
        || false,
    )
    .unwrap();
    let sent = notifier.last().map(|n| n.body).unwrap_or_default();
    let messages = store
        .list_messages(store.list_sessions().unwrap()[0].id)
        .unwrap();
    (sent, messages.last().unwrap().content.clone())
}

#[test]
fn suggestion_is_in_the_brief_only_and_the_notification_is_a_count() {
    let dir = tempdir().unwrap();
    let store = Store::open(&dir.path().join("store.db")).unwrap();
    let (notification, text) = brief(&store, 14);
    assert!(
        text.contains("Possible new clients") && text.contains(ADDRESS),
        "{text}"
    );
    assert!(
        text.contains("Mira Fictive") && text.contains("quote"),
        "{text}"
    );
    assert!(
        notification.contains("1 possible new client"),
        "{notification}"
    );
    assert!(
        !notification.contains("Mira") && !notification.contains(ADDRESS),
        "{notification}"
    );
    assert!(
        store.parties().unwrap().is_empty(),
        "nothing is created on its own"
    );
}

#[test]
fn a_live_party_or_an_ignored_sender_is_not_suggested() {
    let dir = tempdir().unwrap();
    let store = Store::open(&dir.path().join("store.db")).unwrap();
    store
        .insert_party(&NewParty {
            display_name: "Mira Fictive".to_string(),
            emails: vec![ADDRESS.to_string()],
            origin: "owner".to_string(),
            ..NewParty::default()
        })
        .unwrap();
    let (notification, text) = brief(&store, 14);
    assert!(!text.contains("Possible new clients"), "{text}");
    assert!(
        !notification.contains("possible new client"),
        "{notification}"
    );

    let other = tempdir().unwrap();
    let store = Store::open(&other.path().join("store.db")).unwrap();
    assert!(brief(&store, 14).1.contains(ADDRESS));
    store.ignore_sender("Mira.Fictive@Example.invalid").unwrap();
    assert!(
        !brief(&store, 15).1.contains(ADDRESS),
        "ignored on the next brief"
    );
}
