---
name: follow-up
version: 1
command: followup
trigger:
  manual: true
  schedule: null
  on: null
tools: [mail.search, mail.send]
inputs:
  thread: { tier: N }
  tone:   { type: string, default: neutral }
recipients:
  policy: allowlist
approval: each_action
on_failure: stop
---
Find the conversation about {thread} and send a {tone} follow-up.
