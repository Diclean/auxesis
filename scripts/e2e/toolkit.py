#!/usr/bin/env python3
"""The scenario toolkit of the end-to-end runner (stdlib only).

    toolkit.py plan     <scenario.toml>          -> the plan, tab separated
    toolkit.py check    <scenario.toml> <record.json> <provider> <bodies>
    toolkit.py calendar <path>                   -> the EventKit snapshot
    toolkit.py contacts <path>                   -> the demo contacts
    toolkit.py recorder <bodies>                 -> the fake provider

The fact checks (the language, must_contain, must_not_contain) describe what a
real brain must answer, so they only run against a real provider. What the
fake run must still prove is listed per scenario in `fake_expect`.
"""
import datetime
import http.server
import json
import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OWNER = "owner@mailsim.test"  # the owner's own mailbox, never a contact value
WORLD = REPO / "crates/aux-fakemail/src/world.json"  # the demo world's mailbox
TOKEN = re.compile(r"⟦[^⟧]*⟧")  # a privacy placeholder, not a word
# A real reference is a kind, an underscore and twelve hex digits (plus an
# optional suffix). A private turn's system prompt shows the brackets too, so
# only this shape is a tokenised value.
VALUE = re.compile(r"⟦[A-Z][A-Z0-9_]*_[0-9A-F]{12}(?:_[0-9]+)?⟧")
CJK = re.compile("[぀-ヿ㐀-䶿一-鿿가-힯豈-﫿]")


def english(text):
    """English: no CJK and an ASCII-letter ratio above 0.9 (the tokens are cut first)."""
    plain = TOKEN.sub(" ", text)
    letters = sum(1 for c in plain if c.isascii() and c.isalpha())
    others = sum(1 for c in plain if not c.isascii() and c.isalpha())
    if CJK.search(text) or not letters:
        return False
    return letters / (letters + others) > 0.9


def raw_values():
    """The demo world's contact values: the e-mails, phones and bank numbers a gate must hide."""
    text = WORLD.read_text(encoding="utf-8")
    emails = {f for f in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text) if f != OWNER}
    return {"email": emails, "phone": set(re.findall(r"\+\d{9,}", text)),
            "bank": set(re.findall(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,}\b", text))}


# --- the demo world -------------------------------------------------------
#
# The world of crates/aux-fakemail/src/world.json is the fictional mailbox the
# runner starts. Two things are derived from it: the contacts the CRM must
# hold, and the two "who waits for whom" answers the scenarios check.

# The world's bulk mail: the company signs it, the person signs the rest.
BULK = re.compile(r"^General update \d+$")
# The mails a machine sends. A sender whose every mail is one of them is a
# robot (the newsletter, the billing, the calendar, the privacy bait), never
# a client.
MACHINE_TAGS = {"newsletter", "auto-reply", "meeting-invite", "invoice", "sensitive-bait"}
# The mails a prospect sends. A sender whose every mail is one of them is a
# prospect, not a client: the world keeps the two apart.
PROSPECT_TAGS = {"prospect", "quote-request"}
# The world's own marks: a client that waits for the owner, and an owner that
# waits for a client.
WAITING_ON_OWNER = "waiting-on-you"
WAITING_ON_CLIENT = "waiting-on-them"


def world():
    """The demo world: the fictional mailbox of the freelancer."""
    with open(WORLD, encoding="utf-8") as handle:
        return json.load(handle)


def address_of(field):
    """`Name <address>` -> (name, address)."""
    match = re.match(r"^(.*?)\s*<([^>]+)>$", field.strip())
    return (match.group(1), match.group(2)) if match else ("", field.strip())


def world_clients():
    """The demo clients of the world: one card each, the person's name.

    The rule:
    - a robot is a sender whose every mail is a machine mail (the world tags
      those newsletter, auto-reply, meeting-invite, invoice or
      sensitive-bait): the newsletter, the billing, the calendar and the
      privacy-bait institutions are not clients;
    - a prospect is a sender whose every mail is a prospect or a quote
      request: the world keeps the prospects apart from the clients;
    - the owner is never a contact;
    - a card needs the person: the world names the sender on the mails it
      signs itself (the bulk "General update" mails carry the company's
      name, so a sender the world only ever signs with a company name is a
      company channel, not a client);
    - one card per name: a sender with two addresses keeps both e-mails on it,
      and a name the world uses twice is one card, not two.
    """
    names, people, machine, prospect = set(), {}, {}, {}
    for message in world():
        sender, address = address_of(message["from"])
        tags = set(message.get("tags") or [])
        for _, where in [(sender, address)] + [address_of(f) for f in message["to"] + message["cc"]]:
            if where != OWNER:
                names.add(where)
        if address == OWNER:
            continue
        machine.setdefault(address, True)
        prospect.setdefault(address, True)
        if not tags & MACHINE_TAGS:
            machine[address] = False
        if not tags & PROSPECT_TAGS:
            prospect[address] = False
        if not BULK.match(message["subject"]):
            people.setdefault(address, sender)
    cards = {}
    for address in names:
        if machine.get(address, False) or prospect.get(address, False) or address not in people:
            continue  # a robot, a prospect, or a sender the world only signs with a company name
        card = cards.setdefault(people[address], [])
        if address not in card:
            card.append(address)
    return sorted(cards.items())


def world_waiting():
    """Who waits for whom in the demo world: (clients waiting, owner waiting).

    The rule: for every client, the newest mail of each side decides. The
    client's own last mail waits for the owner when the world marks it
    "waiting-on-you" (it asks the owner to confirm something: "we are waiting
    on you"); the owner's last mail to that client waits for the client when
    the world marks it "waiting-on-them" ("waiting on your decision"). A new
    request (a quote, a small extra feature) is a request, not a wait.
    """
    newest_in, newest_out = {}, {}
    for message in world():
        sender, address = address_of(message["from"])
        key = (message["days_ago"], -message["uid"])  # the smallest key is the newest mail
        tags = set(message.get("tags") or [])
        if address == OWNER:
            for _, where in [address_of(f) for f in message["to"] + message["cc"]]:
                if where != OWNER and (where not in newest_out or key < newest_out[where][0]):
                    newest_out[where] = (key, tags)
        elif address not in newest_in or key < newest_in[address][0]:
            newest_in[address] = (key, tags)
    name_of = {address: name for name, addresses in world_clients() for address in addresses}
    on_owner = sorted(name_of[a] for a, (_, tags) in newest_in.items()
                      if WAITING_ON_OWNER in tags and a in name_of)
    on_client = sorted(name_of[a] for a, (_, tags) in newest_out.items()
                       if WAITING_ON_CLIENT in tags and a in name_of)
    return on_owner, on_client


def world_facts():
    """The scenarios whose facts are the world's, and the list each one states."""
    on_owner, on_client = world_waiting()
    return {"follow-up-waiting-on-me": on_owner, "waiting-on-them": on_client}


def fake_check(name, record, replies, bodies):
    """One `fake_expect` entry: what the fake run must still prove."""
    turns = record["turns"]
    if name == "reply_count_one":
        return next((f"turn {i + 1} produced {t['reply_count']} replies" for i, t in enumerate(turns) if t["reply_count"] != 1), None)
    if name == "lang_en":
        return next((f"a reply is not English: {r[:60]!r}" for t in turns for r in t["replies"] if not english(r)), None)
    if name == "approval_asked":
        return None if any(t["approvals"] for t in turns) else "no approval card was raised"
    if name.startswith("provider_saw_") and not bodies.strip():
        return "the provider was never called"
    if name.startswith("provider_saw_no_raw_"):
        values = raw_values()[name[len("provider_saw_no_raw_"):]]
        hit = next((v for v in sorted(values) if v in bodies), None)
        return f"the provider received {hit!r}" if hit else None
    if name == "provider_saw_reply_language":
        return None if "Reply in the language of the message you are answering" in bodies else "no system prompt states the reply language"
    if name == "provider_saw_privacy_token":
        return None if VALUE.search(bodies) else "the provider body holds no privacy token"
    return f"unknown fake_expect {name!r}"


CHECK_KEYS = {"lang", "must_contain", "last_turn_must_contain", "must_not_contain", "max_replies_per_turn", "no_send_without_approval", "approval_asked"}


def check(scenario, record, provider, bodies):
    """The reason the scenario failed, or None when it passed."""
    checks = scenario.get("checks", {})
    turns = record["turns"]
    limit = int(checks.get("max_replies_per_turn", 1))
    for index, turn in enumerate(turns):
        if turn["http"] != 200:
            return f"turn {index + 1} returned HTTP {turn['http']}"
        if not 1 <= turn["reply_count"] <= limit:
            return f"turn {index + 1} produced {turn['reply_count']} replies (max {limit})"
    replies = "\n".join(reply for turn in turns for reply in turn["replies"])
    if checks.get("no_send_without_approval") and record.get("sent", 0):
        return f"{record['sent']} mail(s) left the sandbox without an approval"
    if checks.get("approval_asked") and not any(t["approvals"] for t in turns):
        return "no approval card was raised"
    if provider == "cloud":
        if checks.get("lang") == "en":
            bad = next((r for t in turns for r in t["replies"] if not english(r)), None)
            if bad is not None:
                return f"a reply is not English: {bad[:60]!r}"
        lowered = replies.lower()
        for fact in checks.get("must_contain", []):
            if fact.lower() not in lowered:
                return f"the answer does not mention {fact!r}"
        last = "\n".join(turns[-1]["replies"]).lower() if turns else ""
        for fact in checks.get("last_turn_must_contain", []):
            if fact.lower() not in last:
                return f"the last answer does not mention {fact!r}"
        for banned in checks.get("must_not_contain", []):
            if banned.lower() in lowered:
                return f"the answer mentions {banned!r}"
    else:
        for name in scenario.get("fake_expect", []):
            reason = fake_check(name, record, replies, bodies)
            if reason:
                return f"{name}: {reason}"
    return None


def calendar(path):
    """The EventKit snapshot: two meetings today, one tomorrow, two reminders."""
    now = datetime.datetime.now().astimezone()
    at = lambda d, h, m: (now + datetime.timedelta(days=d)).replace(hour=h, minute=m, second=0, microsecond=0)
    event = lambda i, t, d, h, m, a: {"id": i, "title": t, "start": at(d, h, m).isoformat(), "end": (at(d, h, m) + datetime.timedelta(minutes=30)).isoformat(), "calendar": "Work", "location": None, "attendees": a}
    with open(path, "w") as handle:
        json.dump({"authorized": True,
                   "events": [event("e2e-kickoff", "Call with Camille Example", 0, 9, 30, ["mailto:camille@northwind.example"]),
                              event("e2e-quote", "Quote review with Ines Fictive", 0, 14, 0, []),
                              event("e2e-retro", "Fictional retro tomorrow", 1, 10, 0, [])],
                   "reminders": [{"title": "Send the revised quote to Ines Fictive", "due": at(0, 17, 0).isoformat(), "list": "Work", "completed": False},
                                 {"title": "Fictional archived task", "due": at(0, 9, 0).isoformat(), "list": "Work", "completed": True}]}, handle)


def contacts(path):
    """The vCard of the demo clients: the gate needs them, the card is built from them."""
    with open(path, "w") as handle:
        for name, addresses in world_clients():
            handle.write(f"BEGIN:VCARD\nVERSION:3.0\nFN:{name}\n")
            for address in addresses:
                handle.write(f"EMAIL:{address}\n")
            handle.write("END:VCARD\n")


def recorder(bodies):
    """The fake provider: it echoes the owner text, keeps every request body, answers the invite skill."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            with open(bodies, "ab") as log:
                log.write(body + b"\n")
            request = json.loads(body)
            messages = request["messages"]
            last = max(i for i, m in enumerate(messages) if m["role"] == "user")
            user = messages[last]["content"]
            user = user if isinstance(user, str) else " ".join(p.get("text", "") for p in user)
            message, finish = {"role": "assistant", "content": "[fake:fakey] " + user}, "stop"
            if "skill__send-invite" in [t["function"]["name"] for t in request.get("tools") or []] and "/invite" in user:
                after = messages[last + 1:]
                if any(m["role"] == "tool" for m in after):
                    # The skill came back: a refusal must never read as a send.
                    refused = any("refus" in str(m.get("content", "")).lower() or "deni" in str(m.get("content", "")).lower() for m in after if m["role"] == "tool")
                    message["content"] = "The invitation was not sent: the owner refused the run." if refused else "Invitation sent."
                else:
                    person = user.split("/invite", 1)[1].split(" tomorrow")[0].strip()
                    start = (datetime.datetime.now().astimezone() + datetime.timedelta(days=1)).replace(hour=10, minute=0, second=0, microsecond=0)
                    fill = {"slots": {"person": person, "when": start.isoformat(), "duration": "PT30M"}, "calls": [
                        {"tool": "apple_calendar_create_event", "arguments": {"title": "Meeting with " + person, "start": start.isoformat(), "end": (start + datetime.timedelta(minutes=30)).isoformat()}},
                        {"tool": "mail_send", "arguments": {"to": ["someone@invented.example"], "subject": "Invitation", "body": "Hello, see you tomorrow.", "ics": "event"}}]}
                    call = {"id": "call-1", "type": "function", "function": {"name": "skill__send-invite", "arguments": json.dumps(fill)}}
                    message, finish = {"role": "assistant", "content": "", "tool_calls": [call]}, "tool_calls"
            usage = {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
            if request.get("stream"):
                delta = dict(message)
                if "tool_calls" in delta:
                    delta["tool_calls"] = [dict(delta["tool_calls"][0], index=0)]
                chunk = {"choices": [{"index": 0, "delta": delta, "finish_reason": finish}], "usage": usage}
                out, kind = ("data: " + json.dumps(chunk) + "\n\ndata: [DONE]\n\n").encode(), "text/event-stream"
            else:
                out = json.dumps({"choices": [{"index": 0, "message": message, "finish_reason": finish}], "usage": usage}).encode()
                kind = "application/json"
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    print("recorder on 127.0.0.1:%d" % server.server_address[1], flush=True)
    server.serve_forever()


def main(argv):
    if len(argv) < 3:
        print("usage: toolkit.py plan|check|calendar|contacts|recorder ...", file=sys.stderr)
        return 2
    command = argv[1]
    if command in ("plan", "check"):
        with open(argv[2], "rb") as handle:
            scenario = tomllib.load(handle)
        if command == "plan":
            # A scenario that cannot fail is refused: no turns, an unknown mode or a misspelled check.
            unknown = set(scenario.get("checks", {})) - CHECK_KEYS
            if not scenario.get("turns") or scenario.get("mode", "open") not in ("open", "private") or unknown:
                print(f"bad scenario {argv[2]}: turns, mode or checks {sorted(unknown)}", file=sys.stderr)
                return 2
            # The two "who waits for whom" scenarios state the world's facts: the
            # list must be the derived one, so a scenario that drifted from the
            # world is refused here and not in a cloud run.
            derived = None
            if scenario.get("name", "") in ("follow-up-waiting-on-me", "waiting-on-them"):
                derived = world_facts()[scenario["name"]]
            if derived is not None:
                facts = sorted(scenario.get("checks", {}).get("must_contain", []))
                if not derived or facts != derived:
                    print(f"bad scenario {argv[2]}: must_contain {facts} is not the world's {derived}", file=sys.stderr)
                    return 2
            print(f"{scenario.get('mode', 'open')}\t{scenario.get('agent', 'main')}\t{json.dumps(scenario['turns'])}")
            return 0
        with open(argv[3], encoding="utf-8") as handle:
            record = json.load(handle)
        path = Path(argv[5])
        bodies = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
        reason = check(scenario, record, argv[4], bodies)
        print(f"FAIL {scenario['name']} {reason}" if reason else f"PASS {scenario['name']}")
        return 1 if reason else 0
    if command in ("calendar", "contacts", "recorder"):
        {"calendar": calendar, "contacts": contacts, "recorder": recorder}[command](argv[2])
        return 0
    print(f"unknown command {command!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
