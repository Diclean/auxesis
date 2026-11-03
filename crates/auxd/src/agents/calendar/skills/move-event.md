---
name: move-event
version: 1
command: moveevent
trigger:
  manual: true
tools: [calendar.update_event]
approval: each_run
---
Move or change one event in the owner's calendar. Name it by its exact title in
find_title, and add its event_id only when the conversation shows it. Give only what
changes: a new start and end as local times exactly as the owner said them, with
no offset, or a new title, location or notes. Call the calendar tool once.
