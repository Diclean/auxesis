---
name: log-interaction
version: 1
command: log
trigger:
  manual: true
  schedule: null
  on: null
tools: [crm.log_interaction]
inputs:
  party: { tier: N }
  note: { tier: N }
recipients:
  policy: known-contacts
approval: each_run
on_failure: stop
---
From the owner's short note {note} about {party}, write one interaction with
`crm_log_interaction` and 0 to N memory items. Set the interaction kind from
what happened (note, call or meeting), a summary short enough for the approval
card, the source reference, and only the memory items worth recalling. The
card shows the summary before anything is written; a denied card writes
nothing; when the name is ambiguous the tool lists the parties instead.
