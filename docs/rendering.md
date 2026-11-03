# Rendering of untrusted text

The app shows text that comes from outside the Mac: model replies, messages, tool output, file
names. That text is untrusted. If it were rendered as rich content, a hostile string could read
what is on the screen and send it away without a click.

The rule is short: **the app renders untrusted text as plain text, and never opens a URL found
in text.**

`scripts/check-no-rich-render.sh` enforces it. It scans `apps/auxesis-mac/Sources` for the
patterns that would render or fetch untrusted content: `AttributedString(markdown`,
`NSAttributedString(html`, `WKWebView`, `AsyncImage`, `Link(`, `openURL`,
`NSWorkspace.shared.open`, `.onOpenURL`, and a `LocalizedStringKey` built from a variable. A
match fails the gate. The scan fails closed: a missing source tree, a broken `grep` or an
unreadable tree is a failure, never a clean run.

An exception needs a reviewed change. It is one line per file, with the sha256 of the whole
file, so any later edit to that file fails the gate until the hash is updated. Today there is
one: `SystemOpener.swift`, which opens a fixed System Settings pane and Messages by bundle
id, and takes no URL from text.

So Markdown in a reply is shown as the words the agent wrote, with no link that can be clicked
and no image that can be loaded. `scripts/test-check-no-rich-render.sh` tests the gate itself.
