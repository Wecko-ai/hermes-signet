"""Recognise a tool call that would send email around Signet.

Pure module. It reads the command or script an agent is about to run and names the mailer it
found, or returns ``None``. It is a guard for well-known mailers, not a sandbox: see the README.
"""
from __future__ import annotations

import re
from typing import Any, Optional

# Tools whose arguments are a shell command or a script.
COMMAND_TOOLS = frozenset({"terminal", "execute_code", "process"})
_TEXT_KEYS = ("command", "code", "script", "input")

# A program name counts only where a shell would run it: at the start, after a separator,
# or after a wrapper such as sudo or env.
_AT_COMMAND = (
    r"(?:^|[\n;&|(`]|\$\()\s*"
    r"(?:(?:sudo|exec|env|nohup|time|xargs|command)\s+(?:-\S+\s+)*)*"
    r"(?:[A-Za-z_]\w*=\S*\s+)*"
    r"(?:[\w./~-]*/)?"
)

_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("himalaya send", re.compile(
        _AT_COMMAND + r"himalaya\b[^\n;&|]*?\b(?:(?:message|msg)\s+(?:send|reply|forward)|template\s+send|send)\b",
        re.IGNORECASE)),
    ("sendmail", re.compile(_AT_COMMAND + r"(?:sendmail|msmtp|ssmtp|esmtp|exim4?|postfix\s+sendmail)\b(?!\s+--?(?:version|help)\b)", re.IGNORECASE)),
    ("swaks", re.compile(_AT_COMMAND + r"swaks\b(?!\s+--?(?:version|help)\b)", re.IGNORECASE)),
    ("mail", re.compile(_AT_COMMAND + r"(?:mailx?|s-nail|bsd-mailx)\s+(?:-\w+\s+\S+\s+)*-\w*s\b", re.IGNORECASE)),
    ("mutt", re.compile(_AT_COMMAND + r"(?:neo)?mutt\s+(?:-\w+\s+\S+\s+)*-\w*[sH]\b", re.IGNORECASE)),
    ("curl over SMTP", re.compile(r"\bcurl\b[^\n;&|]*\bsmtps?://", re.IGNORECASE)),
    ("Gmail send", re.compile(
        r"\b(?:gws|gog|gcloud|gmail|google_api(?:\.py)?)\b[^\n;&|]*\bgmail\b[^\n;&|]*\b(?:send|reply|forward)\b"
        r"|" + _AT_COMMAND + r"gmail\b[^\n;&|]*\bsend\b",
        re.IGNORECASE)),
    ("agentmail send", re.compile(r"\bagentmail\b[^\n;&|]*\b(?:send|reply)\b", re.IGNORECASE)),
    ("Apple Mail script", re.compile(r"\bosascript\b[\s\S]*\bMail\b[\s\S]*\bsend\b", re.IGNORECASE)),
    ("PowerShell mail", re.compile(r"\bSend-MailMessage\b", re.IGNORECASE)),
)

# Sending through a library, inside a script.
_LIBRARY = re.compile(
    r"\bsmtplib\b|\baiosmtplib\b|\bSMTP(?:_SSL)?\s*\(|\bnodemailer\b|\bsendmail\s*\(|\bMIMEMultipart\b[\s\S]*\.send"
    r"|\bNet::SMTP\b|\bPHPMailer\b|\bActionMailer\b|\bsmtp\.SendMail\b|\blettre::",
)
_INTERPRETER = re.compile(r"\b(?:python[\d.]*|uv\s+run|node|deno|bun|ruby|perl|php|go\s+run)\b", re.IGNORECASE)

# Hosted mail APIs: the send endpoints, not the whole host.
_API = re.compile(
    r"api\.resend\.com/emails|api\.sendgrid\.com/v3/mail/send|api\.(?:eu\.)?mailgun\.net/v3/[^\s\"']+/messages"
    r"|api\.postmarkapp\.com/email|api\.brevo\.com/v3/smtp/email|mandrillapp\.com/api/[\d.]+/messages/send"
    r"|api\.mailersend\.com/v1/email|api\.agentmail\.to/[^\s\"']*/messages/send|send\.api\.mailtrap\.io/api/send"
    r"|gmail\.googleapis\.com/[^\s\"']*/messages/send|graph\.microsoft\.com/[^\s\"']*/sendMail"
    r"|email\.[a-z0-9-]+\.amazonaws\.com",
    re.IGNORECASE,
)


def _texts(args: Any) -> list[str]:
    if not isinstance(args, dict):
        return []
    return [value for key in _TEXT_KEYS if isinstance(value := args.get(key), str) and value]


def detect(tool_name: str, args: Any) -> Optional[str]:
    """Name of the mailer this call would use, or ``None`` when it sends no mail that Signet knows."""
    if tool_name not in COMMAND_TOOLS:
        return None
    for text in _texts(args):
        for label, pattern in _RULES:
            if pattern.search(text):
                return label
        api = _API.search(text)
        if api:
            return f"mail API ({api.group(0).split('/')[0]})"
        if _LIBRARY.search(text) and (tool_name == "execute_code" or _INTERPRETER.search(text)):
            return "SMTP script"
    return None
