---
name: send-invite
version: 1
command: invite
trigger:
  manual: true
  schedule: null
  on: null
tools: [calendar.create_event, mail.send]
inputs:
  person:   { tier: H }
  email:    { type: email, tier: C, from: contact(person) }
  when:     { type: datetime }
  duration: { type: duration, default: 30m }
recipients:
  policy: known-contacts
approval: each_run
on_failure: stop
---
Create a {duration} event "Meeting with {person}" at {when}, then send the invitation mail with mail_send "ics": "event" so it carries the calendar invite.
Write the mail short and polite, in the language of the conversation. Do not
add anyone else. Do not change the time.
