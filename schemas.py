"""Tool schemas: what the model reads."""

SEND_TOOL = "signet_send_mail"
OUTBOX_TOOL = "signet_outbox"

SEND_MAIL = {
    "name": SEND_TOOL,
    "description": (
        "Send an email. Use this for every outgoing email: the user is shown the exact message "
        "(sender, every recipient, subject, body, attachments) and approves it, and only what they "
        "approved is sent. Do not ask for confirmation in the chat first; calling this tool is how "
        "the user gets asked. Direct mailers (himalaya send, msmtp, sendmail, SMTP scripts, mail "
        "APIs) are blocked here. If the result says the email is held, give the user its code and "
        "stop: they send it with /signet send CODE. Never retry, and never look for another way to "
        "send. There is no Bcc: every recipient is visible on the card."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "to": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Recipients, one address per item. A display name is allowed: \"Ada Lovelace <ada@example.org>\".",
            },
            "cc": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Copy recipients, one address per item. Optional.",
            },
            "subject": {"type": "string", "description": "Subject, on one line."},
            "body": {"type": "string", "description": "Body, in plain text."},
            "from": {
                "type": "string",
                "description": "Sender address. Leave it out to use the address set in the plugin settings.",
            },
            "in_reply_to": {
                "type": "string",
                "description": "Message-ID of the mail this one answers, like <id@host>. Optional.",
            },
            "attachments": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Paths of files to attach. Optional. Credential files are refused.",
            },
        },
        "required": ["to", "subject", "body"],
    },
}

OUTBOX = {
    "name": OUTBOX_TOOL,
    "description": (
        "Read-only. List the emails Signet is holding for the user's approval and the most recent "
        "ones it sent, refused or blocked. Use it to answer \"did my email go out?\". It cannot "
        "send or approve anything."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "description": "How many recent ledger entries to return (default 10, at most 50)."},
        },
        "required": [],
    },
}
