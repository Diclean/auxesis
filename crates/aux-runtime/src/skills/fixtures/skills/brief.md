---
name: brief
version: 2
command: brief
trigger:
  manual: true
  schedule: "0 8 * * *"
  on: null
tools: [crm.today, docs.queue]
inputs:
  focus: { tier: N }
recipients:
  policy: known-contacts
approval: none
on_failure: stop
---
Summarise today's calendar and unread mail, then the CRM section: the parties in
today's events ("who today") and the follow-ups due, read with `crm_today`, and
the documents queue hook (`docs_queue`, empty until C4 fills it). Then propose a
short plan for {focus}.
