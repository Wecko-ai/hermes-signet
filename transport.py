"""Build the message and hand it to the configured transport, once.

Three transports:

``outbox``   write the message as an ``.eml`` file under the plugin's data. Sends nothing. Default.
``command``  give the message on standard input to a local mailer you chose (``himalaya message
             send``, ``msmtp -t``, ``sendmail -t``), run without a shell. That program keeps its
             own configuration; Signet never reads it.
``smtp``     talk to an SMTP server. The password comes from Hermes's secret scope.

A send is never retried here: a second attempt after an unclear failure may deliver twice.
"""
from __future__ import annotations

import hashlib
import mimetypes
import shutil
import smtplib
import ssl
import subprocess
from dataclasses import dataclass
from email import policy
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Any, Callable, Optional

from .core import Draft, DraftError, split_mailbox

TRANSPORTS = ("outbox", "command", "smtp")
DEFAULT_COMMAND = ["himalaya", "message", "send"]
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


@dataclass(frozen=True)
class Delivery:
    ok: bool
    transport: str
    detail: str
    message_id: str = ""
    delivered: bool = False  # False for the outbox transport: written, not sent


class TransportError(RuntimeError):
    """The transport is not usable as configured. Nothing was sent."""


def _mailbox(formatted: str) -> Address:
    """A header address made of the name and address the card showed, encoded by the mail policy."""
    name, address = split_mailbox(formatted)
    return Address(display_name=name, addr_spec=address)


def _seconds(settings: dict[str, Any]) -> float:
    try:
        return min(600.0, max(5.0, float(settings.get("send_timeout") or 60)))
    except (TypeError, ValueError):
        return 60.0


def build_message(draft: Draft, *, seal_header: bool = False) -> EmailMessage:
    """The RFC 5322 message of a draft. Only the draft's fields go in: there is no pass-through."""
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = _mailbox(draft.sender)
    message["To"] = [_mailbox(value) for value in draft.to]
    if draft.cc:
        message["Cc"] = [_mailbox(value) for value in draft.cc]
    message["Subject"] = draft.subject
    message["Date"] = formatdate(usegmt=True)
    message["Message-ID"] = make_msgid(domain=draft.sender_address.rpartition("@")[2] or None)
    if draft.in_reply_to:
        message["In-Reply-To"] = draft.in_reply_to
        message["References"] = draft.in_reply_to
    if seal_header:
        message["X-Signet-Seal"] = draft.digest
    message.set_content(draft.body + "\n", charset="utf-8")
    for item in draft.attachments:
        try:
            data = Path(item.path).read_bytes()
        except OSError as exc:
            raise DraftError(f"attachment cannot be read: {item.name}") from exc
        if hashlib.sha256(data).hexdigest() != item.sha256:
            raise DraftError(f"attachment “{item.name}” changed after it was shown for approval")
        kind, _ = mimetypes.guess_type(item.name)
        maintype, _, subtype = (kind or "application/octet-stream").partition("/")
        message.add_attachment(data, maintype=maintype, subtype=subtype, filename=item.name)
    return message


def _command(settings: dict[str, Any]) -> list[str]:
    command = settings.get("send_command") or DEFAULT_COMMAND
    if isinstance(command, str):
        raise TransportError("send_command must be a list of words, for example [\"msmtp\", \"-t\"], not one string")
    if not isinstance(command, (list, tuple)) or not command or not all(isinstance(word, str) and word for word in command):
        raise TransportError("send_command must be a non-empty list of words")
    program = shutil.which(command[0])
    if not program:
        raise TransportError(f"send_command: “{command[0]}” was not found on this machine")
    return [program, *command[1:]]


def _send_command(message: EmailMessage, settings: dict[str, Any]) -> str:
    argv = _command(settings)
    timeout = _seconds(settings)
    try:
        done = subprocess.run(  # noqa: S603 - a fixed word list from the settings, never a shell line
            argv, input=message.as_bytes(policy=policy.SMTP), capture_output=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{Path(argv[0]).name} did not answer within {timeout:.0f} s") from exc
    if done.returncode != 0:
        tail = (done.stderr or done.stdout or b"").decode("utf-8", "replace").strip().splitlines()[-3:]
        raise RuntimeError(f"{Path(argv[0]).name} exited with {done.returncode}: {' / '.join(tail) or 'no output'}")
    return f"handed to {Path(argv[0]).name}"


def _send_smtp(message: EmailMessage, draft: Draft, settings: dict[str, Any],
               secret: Callable[[str], Optional[str]]) -> str:
    host = str(settings.get("smtp_host") or "").strip()
    if not host:
        raise TransportError("smtp_host is not set")
    security = str(settings.get("smtp_security") or "starttls").lower()
    if security not in ("starttls", "ssl", "none"):
        raise TransportError("smtp_security must be starttls, ssl or none")
    if security == "none" and host not in _LOCAL_HOSTS:
        raise TransportError("smtp_security: none is accepted for a server on this machine only")
    try:
        port = int(settings.get("smtp_port") or (465 if security == "ssl" else 587))
    except (TypeError, ValueError) as exc:
        raise TransportError("smtp_port must be a number") from exc
    username = str(settings.get("smtp_username") or "").strip()
    password = secret("SIGNET_SMTP_PASSWORD") if username else None
    if username and not password:
        raise TransportError("smtp_username is set but the secret SIGNET_SMTP_PASSWORD is not")
    timeout = _seconds(settings)
    context = ssl.create_default_context()
    if security == "ssl":
        server: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
    else:
        server = smtplib.SMTP(host, port, timeout=timeout)
    with server:
        if security == "starttls":
            server.starttls(context=context)
        if username:
            server.login(username, password or "")
        server.send_message(message, from_addr=split_mailbox(draft.sender)[1], to_addrs=draft.envelope_recipients)
    return f"accepted by {host}"


def deliver(draft: Draft, settings: dict[str, Any], *, save: Callable[[Draft, bytes], Path],
            secret: Callable[[str], Optional[str]] = lambda name: None) -> Delivery:
    """Send ``draft`` once through the configured transport. Never raises for a failed delivery."""
    transport = str(settings.get("transport") or "outbox").lower()
    if transport not in TRANSPORTS:
        return Delivery(False, transport, f"unknown transport “{transport}”; use outbox, command or smtp")
    try:
        message = build_message(draft, seal_header=settings.get("seal_header") is True)
        message_id = str(message["Message-ID"])
        if transport == "outbox":
            path = save(draft, message.as_bytes(policy=policy.SMTP))
            return Delivery(True, transport, f"written to {path} (the outbox transport sends nothing)", message_id)
        if transport == "command":
            detail = _send_command(message, settings)
        else:
            detail = _send_smtp(message, draft, settings, secret)
        return Delivery(True, transport, detail, message_id, delivered=True)
    except (TransportError, DraftError) as exc:
        return Delivery(False, transport, f"not sent: {exc}")
    except Exception as exc:  # noqa: BLE001 - a transport failure must come back as a result, not a crash
        return Delivery(False, transport, f"the transport failed, and the mail may or may not have left: {exc}")
