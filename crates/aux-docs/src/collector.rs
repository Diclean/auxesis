//! The receipts collector (row C1).
//!
//! Given one mail account, walk the recent messages through the existing
//! `aux-mail` read path, fetch each message's attachment parts, keep the MIME
//! types MA3 allows, and append the bytes to the evidence registry. The
//! registry deduplicates by SHA-256; the source reference records the account,
//! the IMAP UID and the part id. No message body is ever stored.
//!
//! This is the deterministic `collect-receipts` run: it never calls a model.

use std::sync::Arc;

use aux_mail::{EvidenceAttachment, EvidenceSink, ListQuery, MailApi, MailError};
use serde::Serialize;

/// One attachment the collector refused, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedReceipt {
    /// Sender-declared file name.
    pub file_name: String,
    /// Declared `type/subtype`.
    pub mime: String,
    /// The mail connector's short reason.
    pub reason: String,
}

/// What one collection run did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CollectReport {
    /// Messages the run looked at.
    pub messages: u32,
    /// Parts stored as a new original.
    pub new: u32,
    /// Parts whose SHA-256 was already registered.
    pub deduplicated: u32,
    /// Parts the allow-list, a size cap or the byte budget refused.
    pub skipped: Vec<SkippedReceipt>,
}

impl CollectReport {
    /// The report as the deterministic skill's JSON output.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// A collection failure. It is fail-closed: a sink error aborts the run.
#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    /// The IMAP read path failed.
    #[error("mail: {0}")]
    Mail(#[from] MailError),
    /// The local registry refused a write.
    #[error("evidence registry: {0}")]
    Evidence(String),
}

/// Walk a mailbox and file its receipt attachments.
pub struct ReceiptCollector {
    mail: Arc<dyn MailApi>,
    evidence: Arc<dyn EvidenceSink>,
}

impl ReceiptCollector {
    /// Collect through `mail` into `evidence`.
    pub fn new(mail: Arc<dyn MailApi>, evidence: Arc<dyn EvidenceSink>) -> Self {
        Self { mail, evidence }
    }

    /// Collect the attachments of the messages in `folder` from the last
    /// `days`, at most `limit` messages (`0` means the connector's hard cap).
    pub async fn collect(
        &self,
        account: &str,
        folder: &str,
        days: u32,
        limit: usize,
    ) -> Result<CollectReport, CollectError> {
        let query = ListQuery {
            folder: Some(folder.to_string()),
            limit,
            unread: None,
            days: Some(days),
        };
        let messages = self.mail.list(account, &query).await?;
        let mut report = CollectReport::default();
        for message in messages {
            report.messages += 1;
            let fetched = self
                .mail
                .fetch_attachments(account, folder, message.uid)
                .await?;
            for attachment in fetched.downloaded {
                let reference = self
                    .evidence
                    .append(EvidenceAttachment {
                        sha256: attachment.sha256,
                        file_name: attachment.file_name,
                        mime: attachment.mime,
                        size: attachment.size,
                        bytes: attachment.bytes,
                        account: account.to_string(),
                        folder: folder.to_string(),
                        uid: message.uid,
                        message_id: fetched.message_id.clone(),
                        part: attachment.part,
                    })
                    .map_err(CollectError::Evidence)?;
                if reference.duplicate {
                    report.deduplicated += 1;
                } else {
                    report.new += 1;
                }
            }
            for skipped in fetched.skipped {
                report.skipped.push(SkippedReceipt {
                    file_name: skipped.file_name,
                    mime: skipped.mime,
                    reason: skipped.reason,
                });
            }
        }
        Ok(report)
    }
}

/// The deterministic `collect-receipts` run: no model, no provider.
pub async fn run_collect_receipts(
    mail: Arc<dyn MailApi>,
    evidence: Arc<dyn EvidenceSink>,
    account: &str,
    folder: &str,
    days: u32,
) -> Result<CollectReport, CollectError> {
    ReceiptCollector::new(mail, evidence)
        .collect(account, folder, days, 0)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use aux_mail::{
        DownloadedAttachment, EnvelopeItem, FetchedAttachments, Limits, SkippedAttachment,
    };

    /// One fixture message with one downloaded part and one refused part.
    struct FakeMail;

    fn envelope(uid: u32) -> EnvelopeItem {
        EnvelopeItem {
            uid,
            message_id: format!("<{uid}@fixture.test>"),
            subject: "Receipt".to_string(),
            from: "Northwind Studio <billing@northwind.test>".to_string(),
            to: Vec::new(),
            cc: Vec::new(),
            date: "Mon, 6 Oct 2025 09:00:00 +0000".to_string(),
            size: 128,
            unread: true,
            in_reply_to: None,
        }
    }

    #[async_trait]
    impl MailApi for FakeMail {
        async fn list(&self, _: &str, _: &ListQuery) -> Result<Vec<EnvelopeItem>, MailError> {
            Ok(vec![envelope(1), envelope(2)])
        }

        async fn search(
            &self,
            _: &str,
            _: &aux_mail::SearchQuery,
        ) -> Result<Vec<EnvelopeItem>, MailError> {
            Ok(Vec::new())
        }

        async fn thread(&self, _: &str, _: &str, _: usize) -> Result<Vec<EnvelopeItem>, MailError> {
            Ok(Vec::new())
        }

        async fn read(
            &self,
            _: &str,
            _: u32,
            _: &str,
            _: usize,
        ) -> Result<aux_mail::MailItem, MailError> {
            Err(MailError::Protocol)
        }

        async fn fetch_attachments(
            &self,
            _: &str,
            _: &str,
            uid: u32,
        ) -> Result<FetchedAttachments, MailError> {
            let sha = if uid == 1 {
                "a".repeat(64)
            } else {
                "b".repeat(64)
            };
            Ok(FetchedAttachments {
                message_id: format!("<{uid}@fixture.test>"),
                downloaded: vec![DownloadedAttachment {
                    part: "2".to_string(),
                    file_name: "invoice.pdf".to_string(),
                    mime: "application/pdf".to_string(),
                    size: 4,
                    sha256: sha,
                    bytes: b"data".to_vec(),
                }],
                skipped: vec![SkippedAttachment {
                    part: "3".to_string(),
                    file_name: "archive.zip".to_string(),
                    mime: "application/zip".to_string(),
                    reason: "mime type not allowed: application/zip".to_string(),
                }],
            })
        }

        async fn send(
            &self,
            _: &str,
            _: &aux_mail::OutgoingMail,
        ) -> Result<aux_mail::SendOutcome, MailError> {
            Err(MailError::Protocol)
        }

        fn limits(&self) -> &Limits {
            static LIMITS: std::sync::LazyLock<Limits> = std::sync::LazyLock::new(Limits::default);
            std::sync::LazyLock::force(&LIMITS)
        }
    }

    /// A sink that reports a duplicate when the hash was seen before.
    #[derive(Default)]
    struct FakeSink {
        seen: Mutex<Vec<String>>,
        sources: Mutex<Vec<EvidenceAttachment>>,
    }

    impl EvidenceSink for FakeSink {
        fn append(&self, attachment: EvidenceAttachment) -> Result<aux_mail::EvidenceRef, String> {
            let sha256 = attachment.sha256.clone();
            let mut seen = self.seen.lock().unwrap();
            let duplicate = seen.contains(&sha256);
            seen.push(sha256.clone());
            drop(seen);
            self.sources.lock().unwrap().push(attachment);
            Ok(aux_mail::EvidenceRef { sha256, duplicate })
        }
    }

    #[tokio::test]
    async fn collect_counts_new_duplicates_and_skips() {
        let sink = Arc::new(FakeSink::default());
        let collector = ReceiptCollector::new(Arc::new(FakeMail), sink.clone());
        let report = collector
            .collect("personal", "INBOX", 30, 0)
            .await
            .expect("collect");

        assert_eq!(report.messages, 2);
        assert_eq!(report.new, 2, "two distinct hashes");
        assert_eq!(report.deduplicated, 0);
        assert_eq!(report.skipped.len(), 2, "one zip per message");
        assert!(report.skipped[0].reason.contains("not allowed"));

        let sources = sink.sources.lock().unwrap();
        assert_eq!(sources[0].account, "personal");
        assert_eq!(sources[0].uid, 1);
        assert_eq!(sources[0].part, "2");
        assert_eq!(sources[0].message_id, "<1@fixture.test>");
    }

    #[tokio::test]
    async fn collect_reports_a_sink_refusal_as_an_error() {
        struct RefusingSink;
        impl EvidenceSink for RefusingSink {
            fn append(&self, _: EvidenceAttachment) -> Result<aux_mail::EvidenceRef, String> {
                Err("disk full".to_string())
            }
        }
        let collector = ReceiptCollector::new(Arc::new(FakeMail), Arc::new(RefusingSink));
        let error = collector
            .collect("personal", "INBOX", 30, 0)
            .await
            .expect_err("a refused write aborts the run");
        assert!(matches!(error, CollectError::Evidence(reason) if reason == "disk full"));
    }
}
