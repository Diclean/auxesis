//! Local simulated IMAP/SMTP mailbox for offline Auxesis development.
//!
//! This crate began as `aux-mail`'s in-process test doubles and is reused
//! unchanged: the hand-rolled [`FakeImap`] and [`FakeSmtp`] servers, the
//! `rcgen` self-signed [`TestCert`], the message fixtures and the byte-level
//! helpers. On top of them [`serve`] wires a long-running simulator (the
//! `aux-fakemail` binary) that presents one self-signed certificate, loads a
//! fictional mailbox and mirrors every SMTP submission into `Sent` and an
//! `outbox/` directory.
//!
//! Every fake binds `127.0.0.1` and is reached through an explicit endpoint;
//! nothing here can contact a real server. The mailbox data is fictional.
//!
//! ## Demo world (`aux-fakemail demo --world`)
//!
//! A rich fictional freelancer mailbox (~120 mails over 60 days): ~15 client
//! companies + prospects + partners, both directions, covering waiting-on-you,
//! waiting-on-them, quote requests, e-invoices (one correct, one wrong totals),
//! newsletters with tracking, meeting invites, late-payment and scope-creep
//! threads, plus sensitive-value bait (test IBAN, phone, ID).

#![allow(dead_code, unused_imports)]

mod certs;
mod demo;
mod fake_imap;
mod fake_imap_proto;
mod fake_smtp;
mod fixture;
mod fixtures;
mod raw;
mod serve;
mod static_auth;
mod world;

pub use certs::TestCert;
pub use demo::{demo_mailbox, seed_batch, write_demo};
pub use world::{world_mailbox, write_world};
// Aliases for callers that use other names.
pub use fake_imap::{FakeImap, MailboxHandle};
pub use fake_smtp::FakeSmtp;
pub use fixture::{default_mailbox, StoredMail};
pub use fixtures::{
    fixture_date, fixture_mailbox, fixture_multipart_with_pdf, fixture_multipart_with_zip,
    fixture_oversized, fixture_understated_parts, RawMessage,
};
pub use raw::{read_line, read_until, read_until_tag, send_line};
pub use serve::{serve, SimConfig, SimServer};
pub use static_auth::StaticCredentials;
pub use world::world_mailbox as world;
pub use world::world_mailbox as demo_world;
pub use world::world_mailbox as demo_world_mailbox;
pub use world::write_world as write_demo_world;

/// The one fixed login the simulator accepts, with any password.
pub const SIM_LOGIN: &str = "owner@mailsim.test";
