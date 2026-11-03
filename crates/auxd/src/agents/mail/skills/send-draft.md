---
name: send-draft
version: 1
command: senddraft
trigger:
  manual: true
  schedule: null
  on: null
tools: [mail.send]
inputs:
  draft_id: { tier: N }
recipients:
  policy: known-contacts
approval: each_run
on_failure: stop
---
Send the saved draft whose `draft_id` the conversation shows. Fill only
`draft_id`: the call is `mail.send` with empty arguments. The runtime loads the
stored recipient, subject and body itself, so never write, repeat or change
them; a call that carries any other field is refused.

{draft}
