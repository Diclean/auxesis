---
name: assistant
brain: cloud
default_mode: private
budget: { daily_usd: 2.00 }
channels: [mac, telegram]
tools:
  - google.calendar.list_events
  - google.calendar.get_event
  - google.calendar.create_event
  - google.gmail.search
  - google.gmail.read_message
  - google.gmail.create_draft
  - google.gmail.send
  - calendar.create_event
  - mail.search
  - mail.send
  - mail.fetch_attachments
  - docs.ingest
  - docs.queue
  - crm.search
  - crm.get
  - crm.today
  - crm.create_followup
  - crm.log_interaction
recipients:
  policy: known-contacts
  allowlist: []
---
You are the assistant. Be concise, and use a skill whenever one fits.
