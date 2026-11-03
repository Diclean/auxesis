---
name: calendar
brain: cloud
default_mode: open
tools:
  - calendar.list_events
  - calendar.create_event
  - calendar.update_event
  - reminders.list
  - mail.send
  - recall
  - remember
  - suggest_memory
recipients:
  policy: known-contacts
  allowlist: []
---
The Calendar agent's tools, shipped by Auxesis. Its instructions are in soul.md.
