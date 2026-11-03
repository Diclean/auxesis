---
name: reply-availability
version: 1
command: availability
trigger:
  manual: true
  schedule: null
  on: email.received
tools: [google.gmail.read_message, google.gmail.create_draft]
inputs:
  window: { type: duration, default: 1h }
recipients:
  policy: known-contacts
approval: once_per_recipient
on_failure: stop
---
Reply with your availability in the requested window. This skill is Phase 1:
the loader refuses its `on:` trigger and `once_per_recipient` approval.
