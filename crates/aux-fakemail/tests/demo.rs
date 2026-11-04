//! The daily-use demo mailbox: shape, attachment, and the seed batch.

use aux_fakemail::{demo_mailbox, seed_batch, serve, SimConfig, StoredMail};

const NOW: i64 = 1_792_000_000; // a fixed instant, mid-October 2026

#[test]
fn the_install_set_covers_three_days_with_a_pdf_receipt_and_a_list_mail() {
    let mails = demo_mailbox(NOW);
    assert_eq!(mails.len(), 12);
    let uids: Vec<u32> = mails.iter().map(|m| m.uid).collect();
    assert_eq!(
        uids,
        (1..=12).collect::<Vec<_>>(),
        "oldest first, newest last"
    );
    let receipt = mails
        .iter()
        .find(|m| m.subject.contains("Receipt"))
        .unwrap();
    assert_eq!(receipt.parts.len(), 2);
    assert!(receipt
        .bodystructure
        .as_deref()
        .unwrap()
        .contains("APPLICATION"));
    let news: Vec<_> = mails
        .iter()
        .filter(|m| m.body.contains("List-Unsubscribe:"))
        .collect();
    assert_eq!(news.len(), 1);
    assert!(mails
        .iter()
        .any(|m| m.body.contains("Auto-Submitted: auto-replied")));
    assert!(
        mails.iter().all(|m| m.from.ends_with(".example>")),
        "fictional domains only"
    );
}

#[test]
fn a_seed_batch_continues_the_uids_and_changes_lead_from_day_to_day() {
    let mut mails = demo_mailbox(NOW);
    let first = seed_batch(&mails, NOW);
    assert_eq!(
        first.iter().map(|m| m.uid).collect::<Vec<_>>(),
        vec![13, 14, 15, 16]
    );
    assert!(first.iter().all(|m| m.flags.is_empty()), "all unread");
    assert!(first.iter().any(|m| m.body.contains("List-Unsubscribe:")));
    mails.extend(first.clone());
    let next_day = seed_batch(&mails, NOW + 86_400);
    assert_eq!(next_day[0].uid, 17);
    assert_ne!(first[1].from, next_day[1].from, "a different lead each day");
}

/// A demo mailbox written before the real PDF receipt is
/// re-seeded when the simulator starts: the old receipt attachment becomes
/// the real PDF, and a message the owner added is never touched.
#[tokio::test]
async fn the_demo_receipt_on_disk_is_replaced_by_the_real_pdf_at_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mailbox.json");
    let mut mails = demo_mailbox(NOW);
    // The old format: a `%PDF` header followed by plain text, not a PDF.
    let receipt = mails
        .iter_mut()
        .find(|mail| mail.uid == 5)
        .expect("the receipt");
    receipt.parts[1].1 = "%PDF-1.4\nInvoice VF-2210\nTotal 120.00 EUR\n".to_string();
    // A message the owner added: never touched by the re-seed.
    let mut own = demo_mailbox(NOW).remove(0);
    own.uid = 99;
    own.message_id = "<own-1@mailsim.test>".to_string();
    mails.push(own);
    std::fs::write(&path, serde_json::to_vec_pretty(&mails).unwrap()).unwrap();

    let server = serve(SimConfig {
        dir: dir.path().to_path_buf(),
        imap_port: 0,
        smtp_port: 0,
    })
    .await
    .expect("the simulator starts");
    assert!(server.imap_port > 0);

    let after: Vec<StoredMail> =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let receipt = after
        .iter()
        .find(|mail| mail.uid == 5)
        .expect("the receipt");
    assert!(
        receipt.parts[1].1.contains("(Total 120.00 EUR) Tj"),
        "the receipt is the real PDF now"
    );
    let own = after
        .iter()
        .find(|mail| mail.uid == 99)
        .expect("the owner's message");
    assert_eq!(own.message_id, "<own-1@mailsim.test>");
    assert!(
        own.body.contains("Notes from Friday's call"),
        "the owner's message is untouched"
    );
}
