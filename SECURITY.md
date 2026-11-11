# Security

Signet's job is to keep an email from leaving a Hermes agent without a person's approval of that
exact message. A way around that is a security bug, and we want to hear about it.

## Report

Use GitHub's private reporting on this repository: Security → Report a vulnerability. Please do not
open a public issue for something that lets mail leave unsealed.

Useful reports say which Hermes version and surface (CLI, Desktop, a messaging platform) you used,
what the agent called, and what left.

## In scope

- An email sent by `signet_send_mail` or `/signet send` that a mail client displays differently
  from what the card showed: another recipient, name, subject, text or attachment.
- A seal obtained without a person answering Hermes's approval prompt or typing `/signet send`.
- A held draft that `/signet send` sends without having shown it in full, or after it changed.
- A credential file accepted as an attachment.
- A tool call, of any size or shape, that makes Signet's hook hang or fail for tools other than
  its own.

## Known limits, not bugs

- Signet is a set of hooks inside Hermes, not a sandbox. An agent with a shell that deliberately
  writes its own mailer, hides a command from the guard, or edits the plugin, is outside what hooks
  can stop. The README says how to contain that case.
- The guard recognises a list of well-known mailers, libraries and mail APIs. A mailer missing from
  the list is worth an issue or a pull request, not a private report.
- `trusted_recipients` sends without a prompt by design, to the addresses the owner listed.
