---
name: reply-availability
version: 1
command: availability
trigger:
  manual: true
  schedule: null
  on: null
tools: [mail.send]
inputs:
  person:   { tier: H }
  email:    { type: email, tier: C, from: contact(person) }
  duration: { type: duration, default: 30m }
  topic:    { tier: N, default: a meeting }
recipients:
  policy: known-contacts
approval: each_action
on_failure: stop
---
Send {person} one short mail that proposes the owner's free times for
{topic}, each slot {duration} long. Write the line {free_times} exactly where
the times go: Auxesis replaces it with the times from the owner's calendar.
Never write a date, a day or a clock time yourself, and no digit at all except
in a length such as "30 minutes" or "1 hour". If this conversation shows the
mail you are answering and its subject has no digit, reuse it with "Re: " in
front; otherwise write a short subject about {topic}. Write in the language of the conversation.
Do not add anyone else. Do not promise anything the owner did not say.
