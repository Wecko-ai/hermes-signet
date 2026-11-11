# Changelog

## 0.1.0

First release.

- `signet_send_mail`: an email is shown in Hermes's approval prompt and sent only with a person's
  seal on its SHA-256. The card is ordered for the narrowest prompt, and shows names and subjects
  the way a mail client will.
- Held emails for everything that could not be sealed (YOLO, approvals off, timeouts, scheduled
  runs, denials), with `/signet show`, `/signet send`, `/signet drop`. `/signet send` shows an
  email in full before it seals it.
- Guard on direct mailers in `terminal`, `execute_code` and `process_manage` calls: commands are
  split the way a shell splits them, scripts are judged by what they import and call.
- Deterministic notes on the card: look-alike domains, new recipients, secrets, odd links,
  invisible characters, text that Hermes masks.
- Transports: `outbox`, `command`, `smtp`.
- Local ledger and the read-only `signet_outbox` tool.
