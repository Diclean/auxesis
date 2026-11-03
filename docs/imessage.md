# Messages (iMessage) gateway

The owner talks to Auxesis from the iPhone's Messages app. The Mac runs
Messages signed in to the **agent's own Apple ID**; the agent reads the pinned
chat read-only and replies by AppleScript. This is the base channel of the messaging gateway;
Telegram stays behind the same `Gateway` trait.

Nothing here changes a macOS permission by itself. The owner performs each
grant by hand; the daemon fails closed until the channel is configured and the
permission is present.

## Why a dedicated Apple ID

When the agent shares the owner's Apple ID, its replies land in the wrong
thread or show up as **from me** on the owner's devices, and the owner cannot
tell their own messages from the agent's. Use a **dedicated Apple ID** (a free
iCloud address is enough; no phone number is needed for iMessage). The agent
sends from that Apple ID; the owner reads on the iPhone and never signs the
agent's account in there.

## Set-up

1. **Create the agent's Apple ID.** At `appleid.apple.com`, create a free Apple
   ID for the agent, e.g. `aux-agent@example.test`. Keep its password in the
   owner's password manager, never in a file in this repo.
2. **Sign out the owner's iMessage on the Mac.** Messages → Settings → iMessage
   → *Sign Out*. The owner keeps using iMessage on the iPhone; only the Mac's
   account changes.
3. **Sign in the agent's Apple ID on the Mac.** Messages → Settings → iMessage
   → *Sign in*. Wait until the address is registered and "iMessage is active"
   is shown. The owner's own threads stay on the iPhone.
4. **Clear the local history.** Before the switch, the Mac's `chat.db` held the
   owner's messages. Quit Messages, then remove the historical database with
   the owner's consent (Finder: *Go to Folder* → `~/Library/Messages`, move
   `chat.db*` to the Trash). Auxesis only ever reads rows newer than its
   cursor, but clearing removes the old copy from the Mac.
5. **Pin the chat.** Send one message **from the iPhone to the agent's Apple
   ID**, then read the pinned `guid` from the chat row and put it in
   `gateways.toml` as `chat_guid` (the reader accepts no other chat). The owner
   handle is the iPhone's address in Messages (`+33600000001` or an
   `@example.test` address).
6. **Grant Full Disk Access to the `aux-imessage` helper ONLY.** System
   Settings → Privacy & Security → Full Disk Access → **+**, and add only the
   `aux-imessage` binary (the helper, not the whole app and not the terminal).
   This is what lets the reader open `chat.db` read-only; no other process gets
   it. Messages will also ask once for permission to control Messages
   (Automation → Messages); accept it for the helper only.
7. **Enable the section.** `gateways.toml` under `$AUXESIS_HOME`
   (`~/.auxesis/gateways.toml`), mode 0600, with `enabled = true`:

   ```toml
   [imessage]
   enabled = true
   owner_handles = ["+33600000001", "owner@example.test"]
   chat_guid = "iMessage;-;agent@example.test"
   agent_handle = "agent@example.test"
   mode = "apple_id"
   min_gap_secs = 15
   ```

   Anything missing or malformed leaves the channel **off**; the daemon logs
   the reason without a handle. `owner_handles`, `chat_guid` and `agent_handle`
   are required, `mode` is `apple_id` or `rcs_fallback`, and `min_gap_secs` may
   be raised but never lowered below 15.

## Owner identity

Owner identity comes from `owner_handles` in `gateways.toml` and nowhere else.
The owner may write from several handles — a phone number in E.164 and an email
address — so the list is the union. An inbound row counts as the owner only
when its sender handle matches an entry in the list, comparing email addresses
case-insensitively (a phone number is exact). The gateway never infers "self"
from `message.account` or from `is_from_me` history: on this Mac an old account
once sent as the owner's email, and a history-based self-set silently dropped
every owner message. With config-only identity the owner's email is just
another configured handle and is accepted.

## How the reader is locked

The daemon opens `chat.db` with `SQLITE_OPEN_READ_ONLY` through
`file:…?mode=ro&immutable=0` (plus `PRAGMA query_only`). The query binds the
pinned chat GUID, the ROWID cursor, every owner handle and the limit as
parameters; the `IN (…)` placeholder list is built from the **count**, never
from a value, and the handle comparison is `COLLATE NOCASE` so an email matches
whatever case the sender used. Only `is_from_me = 0` rows from an owner handle
in the pinned chat are returned. Messages with NULL `text` are decoded from
`attributedBody` (a bounded, panic-free typedstream decoder); anything that
does not decode is skipped and counted, never logged as content. Read receipts
come from the agent's own outgoing rows (`is_from_me = 1`, `is_read`,
`date_read`), so "unread urgent" can be reported.

## Send path

Outbound messages target the approved owner participant handle directly. The
sender does not address a chat GUID, so a pinned group chat or a stale GUID
cannot widen the recipient set. The text and handle are passed as `on run argv`
arguments and never interpolated into script source. A failed send is not
retried, so an ambiguous failure cannot double-send.

## Pacing

Live testing on 2026-10-12 showed the iPhone jumps threads when replies arrive
too fast. The gateway therefore waits **at least 15 s after the owner's last
inbound message** and keeps **at least 15 s between two sends**. The clock is
injectable, so the rule is tested; a send that is too early is refused, never
retried.

## RCS fallback

If iMessage registration is unavailable, the owner can run the fallback: the
agent sends RCS/SMS **from line 2 to line 1**, locked to that one chat. Set
`mode = "rcs_fallback"`, `agent_handle` to line 2 and `owner_handles` to line 1,
and keep the pinned `chat_guid` (an `SMS;…` GUID) for inbound reads. Outbound
still targets only the approved participant; only the AppleScript `service
type` changes (`SMS` instead of `iMessage`).

## What the helper does not do

* It has no send command. Every outbound iMessage originates in auxd after the
  privacy kernel admits it; daemon notifications also pass through the notify policy.
* It never reads a `chat.db` it cannot open read-only, and it never creates one.

## The local socket (next step)

The reader starts in-process behind the `InboundSource` trait; that is what
shipped. The helper binary
(`aux-imessage read`) is the process that will hold the read permission once
the **authenticated local socket** lands: a Unix socket at
mode 0600 under `AUXESIS_HOME`, reached with the local token, so `auxd` never
needs Full Disk Access itself. Until then the daemon reads in-process, so the
Full Disk Access grant above currently lands on `auxd`; grant it to whichever
process opens `chat.db`, and move it to the helper when the socket ships.
