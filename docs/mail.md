# Mail — contract (Phase 1)

Status: Phase 1 contract, 2026-10-11. This file lists what Phase 1 keeps, what it changes, and the
stages of work.

## 1. Scope

In: IMAP read (folders, list, search, thread, read), attachment download into the evidence registry,
SMTP send **only from a skill**, never retried, the `.ics` `METHOD:REQUEST` builder, SRV and preset
discovery, the fake IMAP and SMTP servers, the mail path rows (B19, B20, B22), and freezing
`aux-google` behind feature `google`.

Out (Phase 2 or later): mail as a channel, IDLE, drafts, move, delete, reply-all, OAuth for mail,
HTML composition, the Thunderbird ISP database lookup (presets + SRV + own-domain autoconfig only).

## 2. What Phase 1 changes

| Before | Phase 1 |
|---|---|
| `drafts_only` default, `mail_draft`, `mail_move`, `mail_delete`, `mail_reply` | Removed. The only write is `mail.send`, skill-only, approval each run. `send_mode` is removed from config; an old config with it loads with a warning. |
| Attachments never downloaded (`max_attachment_bytes = 0`) | `mail.fetch_attachments` downloads attachments of one message into the evidence registry (§6). Default cap 25 MiB per attachment, 50 MiB per call. |
| Taint guard pending | Taint exists. Every mail tool result taints the session (`untrusted`). No rule can allow `mail.send`; it is skill-only (hardline). |
| `aux-fetch` HTML extractor | `aux_runtime::fetch::readability`. |
| Budgets `UsageKind::MailOps` in `aux-core` | `aux-core` is gone and `kernel_core::budget::UsageKind` has no mail kind; no kernel change. An app-side daily counter in `aux-store` usage with kind `mail_ops` (cap from config, default 500/day). |
| Accounts in `[connectors.mail.accounts]` | Same TOML shape, minus `send_mode`. One account in Phase 1 (the owner's); the config allows several. |
| Password in Keychain | Never the Keychain. `~/.auxesis/.env` (0600) key `AUX_MAIL_<ACCOUNT_ID_UPPER>`, through the existing `.env` store. |

## 3. Tools

| Logical | Wire | Kind | Path row |
|---|---|---|---|
| `mail.list` | `mail_list` | read | B19 |
| `mail.search` | `mail_search` | read | B19 |
| `mail.thread` | `mail_thread` | read | B19 |
| `mail.read` | `mail_read` | read | B19 |
| `mail.fetch_attachments` | `mail_fetch_attachments` | local write (append-only registry) | B22 |
| `mail.send` | `mail_send` | write, **skill-only** | B20 |

Schemas: the four reads keep their existing schemas. `mail_fetch_attachments { account, folder?, uid }` → list of
`{sha256, file_name, mime, size, duplicate}`, no bytes. `mail_send { account?, to[], cc?, subject,
body, ics? }` where `ics` is the opaque id of an invite built by the runtime (§5), never text from the
model. All `deny_unknown_fields`, all bounded; header fields reject control characters.

The tool map (`aux-runtime::skills::tool_map`) gains these names. `send-invite` and `follow-up` use
`mail.send`. `google.*` names stay in the map only when feature `google` is on.

## 4. Read path

The read path: pull only, ENVELOPE first, `BODY.PEEK[]`, never `\Seen`,
plain part preferred, HTML through the mail extractor (the whole body, without hidden elements
or text hidden by inline style), the untrusted banner on every result,
the hard bounds. Results go to the model through the session gate (Private: tokenised).

Threads are computed from envelopes, no store cache in Phase 1. The CRM timeline (B3)
stores references, not bodies.

## 5. Send path and the invite

`mail.send` is reachable only from `skill__<name>` (broker hardline, like `google.gmail.send` today).
The executor rehydrates, checks recipients per value, and calls `MailService::send` once. No retry,
ever. One Ledger `skill.action` row; `mail.call` row without content or recipients.

A failure **after** the server accepted `DATA` is not a failure: the connection or its final reply
failed, so the mail may be out. The run, `skill.action` and `mail.call` rows say `uncertain`, the
result tells the model the mail may have been sent and must not be resent, and a draft caught this
way can never be sent again. Failures before `DATA` still say `failed` and are never retried.

**Invite.** `send-invite` runs two calls: `calendar.create_event` (EventKit, through the Mac bridge,
`docs/phase1.md` §3) and `mail.send` with `ics: "event"`. The runtime builds the `.ics` from the
**rehydrated** event arguments after approval:

```text
BEGIN:VCALENDAR / VERSION:2.0 / PRODID:-//Auxesis//Phase 1//EN / METHOD:REQUEST
BEGIN:VEVENT
UID:<event_id from EventKit>@auxesis.local   DTSTAMP:<now UTC>
DTSTART/DTEND: UTC (Z form)                   SUMMARY:<title>
ORGANIZER;CN=<owner display>:mailto:<account address>
ATTENDEE;CN=<person>;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:<recipient>
SEQUENCE:0   STATUS:CONFIRMED
END:VEVENT / END:VCALENDAR
```

Lines folded at 75 octets, CRLF endings, text escaped per RFC 5545 §3.3.11. Attached as
`text/calendar; method=REQUEST; charset=UTF-8` (inline part) plus `invite.ics`. The `.ics` and the
body must contain no `⟦` or `⟧`. Calendar first, then mail; if the calendar call fails, the mail is
not sent (skills rule: failure stops the run).

## 6. Attachments into the registry

`mail.fetch_attachments` downloads each attachment part (`BODY.PEEK[<part>]`) whose MIME type is
`application/pdf`, `application/xml`, `text/xml`, `image/jpeg`, `image/png` or `image/heic`, up to the
caps. Each is hashed (sha256) and appended to the evidence registry with the source reference
`{account, folder, uid, message_id, part, file_name}`. A known sha256 is
not stored twice; the new source reference is added. Bytes never reach a model. Other types are
listed and skipped with a reason.

## 7. Setup

`aux mail add <address>` runs discovery: preset by domain, then SRV (`_imaps._tcp`, prefer 993
implicit TLS; `_submission._tcp` 587 STARTTLS or `_submissions._tcp` 465), then
`autoconfig.<domain>`, then the preset table. Candidates are shown, never picked silently. The
password is read without echo into `.env`. `aux mail test` connects once and prints
"Connected. N folders, M unread in INBOX." The app's setup screen is planned for a later phase.

## 8. Stages

| Stage | Content | Done when |
|---|---|---|
| 1 | Presets, error vocabulary, dial + TLS (`tokio-rustls`, one config in a `OnceLock`), fake IMAP + fake SMTP | The presets, error vocabulary, dial and TLS tests pass. |
| 2 | Read path, parse, sanitise, banner | The read, parse, sanitise and banner tests pass (minus attachment quarantine). |
| 3 | Read tools + registration in `auxd` (agent grants, path B19 via the session gate) + `mail.fetch_attachments` (B22) + `aux mail add/test/list/search/read` | Tools visible only with a grant; Private turn: provider sees tokens for a fixture sender; an attachment of a fixture mail lands in the registry, deduplicated. |
| 4 | SMTP send + `.ics` builder + skill-only wiring + `send-invite` and `follow-up` on `mail.send` + EventKit bridge call (needs the Mac bridge) + `aux-google` behind feature `google` + hero test rewired to fake SMTP and the fake bridge | `mail.send` from a plain conversation refused before any socket; one send, no retry on `421` (fake sees one `MAIL FROM`); hero test green on fake SMTP with an `.ics` whose attendee is the real address and with no `⟦ ⟧`; default build has no Google code (`cargo tree -e features` and `rg google_` in the default binary symbols). |

`check-egress.sh` must pass on every stage: mail opens raw sockets (no `reqwest`), so stage 1 adds the
dialer to `docs/egress.md` under a new "raw sockets" table and the script learns to check it.

## 9. One command setup (simulated mailbox, 08:00 brief)

`scripts/brief-setup.sh --owner` keeps the local `aux-fakemail` (fictional mails, loopback only, one
new mail a day) running as the LaunchAgent `com.auxesis.fakemail`, adds the `fakemail` account to
`config.toml`, and sets `[brief] enabled = true`, `time = "08:00"` (`.bak` kept; re-running changes
nothing). With the env vars `AUX_OWNER_HANDLES` (comma list), `AUX_AGENT_HANDLE` and `AUX_CHAT_GUID`
(env only, so they never appear in `ps`) it also writes `gateways.toml` (0600), `docs/imessage.md`
step 7. If another program holds loopback port 14143, setup stops with an error and writes no mail
config; pass `--imap-port N`. No macOS permission changes.

## 10. Fictional demo mailbox

`aux-fakemail demo --dir <dir>` writes a fictional set of twelve mails from the last three days (two
quote or availability requests, one referral, a newsletter, an auto-reply, two clients, a PDF
receipt); `--seed` adds one fresh "today" batch. Every name and address is invented (`.test`,
`.example`). `scripts/brief-setup.sh` installs and runs the simulator on the Mac.
