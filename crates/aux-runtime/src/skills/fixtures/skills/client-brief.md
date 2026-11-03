---
name: client-brief
version: 1
command: client
trigger:
  manual: true
  schedule: null
  on: null
tools: [crm.get]
inputs:
  name: { tier: N }
recipients:
  policy: known-contacts
approval: none
on_failure: stop
---
Given the client name {name}, read the party with `crm_get`. When several
parties match, `crm_get` returns them: list them and ask the owner to pick one;
never guess. Otherwise write a short brief: identity, the last five timeline
items, the open follow-ups and the memory items. This skill is read-only, so
write nothing.
