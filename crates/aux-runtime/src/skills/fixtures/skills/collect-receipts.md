---
name: collect-receipts
version: 1
command: collect-receipts
brain: none
trigger:
  manual: true
tools: [docs.ingest]
recipients:
  policy: known-contacts
approval: none
on_failure: stop
---
Collect the PDF, XML and image attachments of recent mail into the local
evidence registry, then report the counts: new, deduplicated, and skipped with
a reason. The collector is deterministic: no model runs, and no message body is
ever stored.

Run this skill yourself whenever a document lookup finds nothing: it is local
work on this Mac, it needs no approval, and it never asks the owner. Look
again after the collect: the receipt is filed, and the Mac reads it later.
