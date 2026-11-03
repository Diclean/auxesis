# Phase 1 — behaviour contract

Status: Phase 1 contract, 2026-10-11. This file describes the kernel path rows, the Mac bridge,
the kernel changes, tool names, the nightly run and recipient resolution. The area contracts are
[providers](providers.md), [mail](mail.md), [iMessage](imessage.md) and [egress](egress.md).

## 1. Open decisions and their defaults

| # | Item | Default (reversible) |
|---|---|---|
| 1 | IMAP/SMTP account | Build against the fake servers and the seven presets. The live smoke needs a real account. |
| 2 | Calendar for new events | `[calendar] target` in `config.toml`, by calendar title. Absent: EventKit's `defaultCalendarForNewEvents`. |
| 3 | Receipt sources | Mail attachments only. A drop folder is a small follow-up if asked. |
| 4 | Workshop languages | Python scripts only (`/usr/bin/python3`, standard library only). Rust crates later. |
| 5 | Keys for cloud models | Local app keys live in `~/.auxesis/.env`. CI does not read that file or touch the real Keychain. The optional cloud nightly runs on a Mac runner; its repository secret goes only to the sandboxed test and a presence-only summary. |

## 2. Path rows (kernel `PathId::ALL`)

New rows are added by the kernel change that needs them. Numbers are fixed here so later changes do
not collide.

| Row | Label | Private | Open |
|---|---|---|
| B1, B2, G3 | memory recall / remember / store (storage) | Allow (Covered) | Allow |
| B16 | (deleted: external CRM) | Disabled | Disabled |
| B19 | IMAP read: list, search, thread, read (tool results through the session gate) | Allow (Covered) at flip | Allow |
| B20 | Mail send over SMTP, skill-only, real values after approval | AskEachTime(FilteredRecipients) | Allow |
| B21 | EventKit create/update event, skill-only, through the Mac bridge | AskEachTime(FilteredRecipients) | Allow |
| B22 | IMAP attachment download into the evidence registry (local only) | Allow (Covered) at flip | Allow |
| B23 | CRM read into a provider context | Allow (Covered) at flip | Allow |
| G8 | CRM store (SQLCipher) | Allow (Covered) at flip | Allow |
| B24 | Document fields and check results into a provider context | Allow (Covered) at flip | Allow |
| G5 | Documents store (v17 `documents`, `proofs`, v21 `evidence_source`, v23 `document_fields`) | Allow (Covered) at flip | Allow |
| B25 | Vision OCR through the Mac bridge (local only) | Allow (Covered) at flip | Allow |
| B26 | Workshop tool output into a provider context | Allow (Covered) at flip | Allow |
| B11 | EventKit read (calendar snapshot) into a provider context | Allow (Covered) at flip | Allow |

"Covered" means every byte the row carries to a provider passes `admit()` and a `Gate`. A row is
marked Covered in the same kernel tag as the app change that makes it true, never before. The app
pins the kernel revision that makes it true. "at flip" means the row is added `NotCovered` (Disabled
in Private) and becomes Covered only in the kernel commit pinned by the app change that makes it
true. Every row in this table follows that rule.

## 3. The Mac bridge

`auxd` cannot call EventKit or Vision; the app can. One request/response channel, shared by both:

1. `auxd` publishes a frame on the existing loopback WebSocket:
   `{"type":"bridge.request","id":"<uuid>","op":"eventkit.create_event"|"eventkit.update_event"|"vision.ocr","args":{…}}`.
2. The app runs the op and answers `POST /v1/bridge/{id}` with the local token:
   `{"ok":true,"result":{…}}` or `{"ok":false,"error":"<code>","message":"…"}`.
3. `auxd` waits at most 30 s (OCR: 60 s). No app connected, or no answer → typed error
   `bridge_unavailable` ("Open the Auxesis app on this Mac"). A request id answers once; a second POST
   is `409`. An unknown id is `404`. Missing or wrong token is `401` and nothing runs.
4. Every request and answer writes one Ledger row `bridge.request` / `bridge.result` with op, id,
   outcome, duration; never an argument value.
5. Tests drive the bridge with a fake app (a WS client in the test) in CI; the real EventKit and Vision
   paths are checked by hand on a Mac.

`eventkit.create_event` args: `{calendar?, title, start, end, location?, notes?, url?}` (RFC 3339 times,
title ≤ 200 chars, notes ≤ 8 KiB). Result: `{event_id, calendar}`. Attendees are never sent to
EventKit (it cannot add them); the invite goes by mail with an `.ics` (`docs/mail.md` §5).
`vision.ocr` args: `{sha256}` of a registry document; the app reads the bytes from `auxd`
(`GET /v1/documents/{sha256}/bytes`, local token), runs `VNRecognizeTextRequest` (accurate, language
correction on, languages `en-US, fr-FR`), and returns `{lines:[{text, confidence, box}], pages}`.

## 4. Kernel changes

**Secrets.** Secrets are dropped in every mode, and JSON keys give their values context.
1. A `Secret` span is replaced in **both** policies. `Tokenised` keeps today's `⟦SECRET_…⟧` token.
   `Passthrough` replaces the span with the fixed text `[secret removed]` and counts it in the report.
   No other kind changes. `Passthrough` applies the same rule to IBAN
   (`[iban removed]`), payment card (`[card removed]`), national ID / passport / MRZ (`[id removed]`)
   and health (`[health removed]`). Names and ordinary text stay in clear.
2. `Gate::value` checks every object entry whose value is a string also as the text `"<key>: <value>"`.
   A `Secret` span found there that covers value bytes masks the value (both policies, rule 1). Keys
   are still masked on their own as today.
3. Tests: `{"password":"hunter2-Very-Secret"}` in Open → value `[secret removed]`; same in Private →
   `⟦SECRET_…⟧`; `{"note":"my password is X9!kq-22"}` unchanged behaviour from the earlier rule in both; nested
   arrays and objects; a non-secret key (`{"city":"Paris"}`) is untouched in Open; no regression on the
   existing corpus; a value over the secret read cap still fails closed in Private and is replaced in
   Open.

**Registry rows, conservative first.** Adds B19–B22 with the §2 labels; `slice` names the change
that adds the row. B19 and B22 start `NotCovered`, Disabled in Private; B20 and B21 start
`NotCovered`, `AskEachTime(FilteredRecipients)` in Private (like the existing send rows). B16
becomes `"deleted (external CRM)"`, Disabled in both modes. B1, B2, G3 are unchanged. The registry
tests count the new totals. No other kernel change.

**Memory.** B1, B2, G3 become `Covered`, Allow in Private. The app pins the kernel revision that
makes it true.

**Mail read, attachments, calendar read.** B19, B22 and B11 become `Covered`, Allow in Private. The
app change that makes it true proves that mail and calendar tool results reach a provider only
through the session gate in Private.

**Documents store.** G5 flips next to B24/B25.

## 5. Tool names

The logical names map to concrete tools as follows. `calendar.read` = the EventKit snapshot read
tool (B11); `calendar.create_event` = the bridge tool (B21); `mail.read` = `mail.list`,
`mail.search`, `mail.thread`, `mail.read` (B19); `mail.read(attachments)` =
`mail.fetch_attachments` (B22); `mail.send` (B20); `crm.read` = `crm.search`, `crm.get` (B23);
`crm.write` = `crm.log_interaction`, `crm.create_followup`, `crm.update_party` (G8); `docs.*` for
documents; `workshop.create` for the workshop.

## 6. Honest nightly

The nightly matrix has one leg per configured brain. A leg whose brain is unreachable or has no key
exits with code 0 **and** writes `skipped: <brain>: <reason>` to the job summary; the workflow's final
step fails the run if any leg marked `required` (from `qa/acceptance/brains.toml`) was skipped. For
Phase 1, required = `fake`; `deepseek`, `anthropic`, `ollama-cloud` are reported, not required, until
keys are configured. A test that returns early on a brain counts as `skipped` for that brain, not
`passed`.

## 7. Recipient from contacts

An `email` input may declare `from: contact(<slot>)` where `<slot>` is a `tier: H` input. The runtime,
not the model, fills it: after the model fills `<slot>` with a person token, the executor rehydrates
the person, looks the name up in the `ContactIndex`, and uses that contact's address. Zero or several
addresses → the run is refused before the card with a plain reason that names the person by token,
never by value (`no address for ⟦PERSON_1⟧`, `several addresses for ⟦PERSON_1⟧; say which one`).
The model's schema no longer contains a derived slot, so the model cannot invent one. Calls that name
the derived slot get the resolved value. `send-invite.md` declares `email: { type: email, tier: C,
from: contact(person) }`. Loader: `from:` naming a missing or non-H slot is a load error.
