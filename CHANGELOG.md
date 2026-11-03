# Changelog

All notable changes to Auxesis are recorded in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); releases use
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

The first public release. Auxesis is a personal assistant that runs on one Mac: a
daemon keeps working while you are away, a native app shows what happened, and
a privacy kernel decides what may leave the machine.

### Added

**Chat with Aux**

- Talk to Aux in the app, in the terminal, or by text message, and it answers in your language.
- Aux hands the work to the Mail, Calendar, Clients and Documents agents, checks your calendar, mail and client book before it states a fact about them, and tells you what each one did.
- Start a new conversation with any agent; the old one stays on this Mac and you can make it current again.
- Point Auxesis at the model provider you already pay for and use your own key; a fallback provider is tried when the first one fails.
- Aux keeps what it learned: read it, edit it, forget it, and accept or ignore what it suggests.
- Ask a web page to tell you when it changes; Aux texts you a short yes-or-no question, and the text never carries mail, client or routine content.

**Mail**

- Read your mail over IMAP: list it, search it, open a thread, read a mail, and fetch its attachments into a local store on this Mac. The newest mail comes first.
- Send mail over SMTP only after you approve a card that shows exactly what leaves.
- After your yes, the Mail agent can send a follow-up to a known contact, with your free times attached.
- The morning brief explains your mail in the app; in Private mode your phone gets a fixed notice instead.

**Calendar**

- Read your calendar into an encrypted snapshot on this Mac: each event appears once, across all your calendars.
- Ask for a free slot and Aux answers with your free times; send an invite after you approve the card, and it lands at the right local time.
- The Agenda page shows how fresh your calendar copy is, and Aux says when the copy is out of date.

**Clients and CRM**

- A client card shows its mail and its meetings, you can log an interaction on it, and search finds your clients by name.
- Turn a mail sender into a client, take a possible new client straight from the brief, or import clients and contacts with a preview before anything is saved.
- Forget a client, or merge two of them.

**Documents**

- Collect the receipts that reach you by mail, link each one to its client, and see them on a Documents page in the app.
- Read a document with the personal data inside it hidden, and export the receipts of a period to a spreadsheet and the original files.

**Privacy kernel**

- Private mode (the default) — every class listed below is replaced by a token before the text is sent, and the real value is put back on the Mac.
- Open mode (you opt in) — e-mail addresses and phone numbers are sent as written. Postal addresses, payment cards, IBANs, national IDs, health details and secrets are still removed, in every mode.
- What is hidden:
  - e-mail addresses
  - phone numbers
  - postal addresses (also in Open mode)
  - payment card numbers (also in Open mode)
  - IBANs (also in Open mode)
  - national identity numbers, passports and other government identifiers (also in Open mode)
  - health details (also in Open mode)
  - secrets: API keys, tokens and passwords (also in Open mode)
- The mode is resolved per turn from the global setting, the agent's own setting and the conversation's setting; the most restrictive one wins, and a setting that cannot be read is treated as Private.
- A value keeps the same placeholder across turns and agents, and no marker ever reaches the answer; names and company names pass as written.
- Text fetched from the web is marked as untrusted and handled as data, never as instructions.

**Approvals and cards**

- Shell commands and sends open an approval card first, a clean command is checked by another model before its card appears, and nothing runs until you allow it.
- The card shows exactly what leaves, a yes sends only the version the card shows, and Cancel or Undo drops a draft edit.
- Under the auto mode, only sends, payments, deletes, account changes and unknown tools ask; reads, delegations and a write in your own client book run without a card.
- The shell runs under a macOS sandbox profile: no network unless you allow it, and writes limited to the workspace.
- Web fetches of hosts the app has vetted run without a card in the default mode; a stricter mode asks for those too.
- Every agent has daily caps on tokens, spend and connector calls.

**The Mac app**

- A native app with three panes: Today, Waiting for you, and Since you left.
- Today holds the morning brief, Waiting for you holds the cards that need a decision, and Since you left is a plain ledger of what happened while you were away.
- The sidebar shows how many requests left the Mac today, and Ask Aux in the toolbar opens an agent's own conversation.
- A Work, Team and Privacy panel, an Agents and rules page, a Team map, and a Privacy record page that lists every request and what it carried.
- Replies render as tables, lists and code, and a hidden value shows as a neutral chip.
- Stop all pauses every agent at its next step, and a stop report says what was paused; Resume brings them back.
- A setup screen asks for Calendar, Notifications, Messages and Full Disk Access when it needs them, and the app speaks English and French.

**The command line**

- `aux doctor` checks that this machine can run Auxesis, and `aux status` shows the daemon's state.
- `aux chat` talks to an agent with the same tools as the app, and `aux brief` sets up and reads the morning brief.
- `aux install` and `aux uninstall` keep the daemon running between reboots, `aux stop` pauses everything and `aux resume` brings it back.
- `aux secret set` stores a provider key; `aux secret check` confirms it without printing it.
- `aux mail`, `aux crm`, `aux docs`, `aux contacts`, `aux memory`, `aux mcp`, `aux ext` and `aux skill` work on your data from the terminal, while `aux usage` and `aux activity` show what the agents did and what they cost.

### Known limits

- The app bundle is signed ad-hoc and is not notarised, so the first open asks you to confirm it: right-click the app, choose **Open**, then **Open Anyway**.
- macOS on Apple Silicon only. Linux and Windows are not supported.
- Build from source for now: no notarised `.dmg` has been published yet.
- A single user on a single Mac: there is no account system, no server and no multi-user mode.
- Auxesis never ships a model. You point it at a provider you already pay for and bring your own key.
- The kernel can only hide what it can recognise, so it is a filter with limits, not a guarantee. Do not rely on it for data you would not want a provider to see. The measured recall per class is in the README section [How well the privacy filter works](README.md#how-well-the-privacy-filter-works).
- The architecture and the interface still change often, and there is no support promise yet.
