# Changelog

## 0.1.0

First release.

- `signet_send_mail`: an email is shown in Hermes's approval prompt and sent only with a person's
  seal on its SHA-256.
- Held emails for everything that could not be sealed (YOLO, approvals off, timeouts, scheduled
  runs), with `/signet show`, `/signet send`, `/signet drop`.
- Guard on direct mailers in `terminal` and `execute_code` calls.
- Deterministic notes on the card: look-alike domains, first-time recipients, secrets, odd links,
  invisible characters.
- Transports: `outbox`, `command`, `smtp`.
- Local ledger and the read-only `signet_outbox` tool.
