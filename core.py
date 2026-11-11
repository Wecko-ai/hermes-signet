"""Canonical form, fingerprint and review card of an outgoing email.

Pure module: no Hermes imports, no network, no writes. Everything Signet shows a person and
everything it later sends is built from the :class:`Draft` made here, so the two cannot differ.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from email.utils import formataddr, getaddresses
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import urlsplit

MAX_RECIPIENTS = 20
MAX_ATTACHMENTS = 10
MAX_ATTACHMENT_BYTES = 20 * 1024 * 1024
MAX_BODY_CHARS = 200_000
MAX_SUBJECT_CHARS = 400


class DraftError(ValueError):
    """The draft cannot be sent as written. The message is safe to show to the model."""


# Zero-width and bidirectional controls: text a reader cannot see on the card must not travel.
_INVISIBLE_RANGES = ((0x00AD, 0x00AD), (0x180E, 0x180E), (0x200B, 0x200F), (0x202A, 0x202E),
                     (0x2060, 0x2064), (0x2066, 0x2069), (0xFEFF, 0xFEFF))
_INVISIBLE = re.compile("[" + "".join(f"\\u{low:04x}-\\u{high:04x}" for low, high in _INVISIBLE_RANGES) + "]")
_CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ADDRESS = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_MESSAGE_ID = re.compile(r"^<[^<>\s]{1,300}>$")
_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_ADDRESS_IN_TEXT = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# File names that hold credentials. Signet refuses to attach them: a person who really wants to
# mail a key can do it by hand.
_CREDENTIAL_NAMES = re.compile(
    r"(?:^|/)(?:\.env(?:\.[\w.-]+)?|\.netrc|\.pgpass|auth\.json|credentials(?:\.json)?|"
    r"id_(?:rsa|dsa|ecdsa|ed25519)|[\w.-]+\.(?:pem|p12|pfx|keychain|kdbx))$",
    re.IGNORECASE,
)
_PRIVATE_KEY_BYTES = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_CREDENTIAL_DIRS = re.compile(r"(?:^|/)\.(?:ssh|aws|gnupg|kube)/", re.IGNORECASE)

_SECRET_PATTERNS = (
    ("a private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("an AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("a GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("an API key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("a Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("a Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("a signed token (JWT)", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
)

_COMMON_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
    "icloud.com", "me.com", "proton.me", "protonmail.com", "aol.com", "gmx.com", "fastmail.com",
})


@dataclass(frozen=True)
class Attachment:
    path: str
    name: str
    size: int
    sha256: str


@dataclass(frozen=True)
class Draft:
    """One outgoing email in canonical form. Immutable: a change is a new draft, with a new seal."""

    sender: str
    to: tuple[str, ...]
    cc: tuple[str, ...]
    subject: str
    body: str
    in_reply_to: str = ""
    references: str = ""
    attachments: tuple[Attachment, ...] = ()
    removed_invisible: int = 0

    @property
    def sender_address(self) -> str:
        return _address_of(self.sender)

    @property
    def recipient_addresses(self) -> list[str]:
        return [_address_of(value) for value in (*self.to, *self.cc)]

    def canonical(self) -> dict[str, Any]:
        return {
            "v": 1,
            "from": self.sender,
            "to": list(self.to),
            "cc": list(self.cc),
            "subject": self.subject,
            "body": self.body,
            "in_reply_to": self.in_reply_to,
            "references": self.references,
            "attachments": [[item.name, item.size, item.sha256] for item in self.attachments],
        }

    @property
    def digest(self) -> str:
        """SHA-256 of everything that travels. The seal a person gives is a seal on this value."""
        text = json.dumps(self.canonical(), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @property
    def code(self) -> str:
        """Short form of the digest that a person can read and type: ``7F3A-91C2``."""
        return format_code(self.digest)

    def to_record(self) -> dict[str, Any]:
        record = self.canonical()
        record["attachments"] = [
            {"path": item.path, "name": item.name, "size": item.size, "sha256": item.sha256}
            for item in self.attachments
        ]
        return record


def format_code(digest: str) -> str:
    head = digest[:8].upper()
    return f"{head[:4]}-{head[4:]}"


def normalize_code(text: str) -> str:
    """``7f3a91c2``, ``7F3A-91C2`` and `` 7f3a-91c2 `` are the same code. Empty when malformed."""
    compact = re.sub(r"[^0-9A-Fa-f]", "", text or "").upper()
    return f"{compact[:4]}-{compact[4:]}" if len(compact) == 8 else ""


def _address_of(formatted: str) -> str:
    pairs = getaddresses([formatted])
    return pairs[0][1].lower() if pairs else ""


def _clean_line(value: Any, what: str, limit: int) -> tuple[str, int]:
    """One header value: text on a single line, without invisible characters."""
    if value is None:
        return "", 0
    if not isinstance(value, str):
        raise DraftError(f"{what} must be text")
    if "\n" in value or "\r" in value:
        raise DraftError(f"{what} contains a line break, which a mail header cannot hold")
    text = unicodedata.normalize("NFC", value)
    cleaned = _CONTROL.sub("", _INVISIBLE.sub("", text))
    removed = len(text) - len(cleaned)
    cleaned = cleaned.strip()
    if len(cleaned) > limit:
        raise DraftError(f"{what} is longer than {limit} characters")
    return cleaned, removed


def _as_list(value: Any, what: str) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        return list(value)
    raise DraftError(f"{what} must be a list of text values")


def _parse_addresses(value: Any, what: str) -> tuple[list[str], int]:
    """Formatted, validated, de-duplicated addresses. Display names are kept, cleaned."""
    removed = 0
    lines = []
    for raw in _as_list(value, what):
        cleaned, count = _clean_line(raw, what, 2000)
        removed += count
        if cleaned:
            lines.append(cleaned)
    result: list[str] = []
    seen: set[str] = set()
    for name, address in getaddresses(lines):
        address = address.strip()
        if not address and not name:
            continue
        if "@" not in address:
            raise DraftError(f"{what}: “{address or name}” is not an email address")
        local, _, domain = address.rpartition("@")
        try:
            domain = domain.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise DraftError(f"{what}: the domain of “{address}” is not valid") from exc
        address = f"{local}@{domain}"
        if not _ADDRESS.match(address):
            raise DraftError(f"{what}: “{address}” is not a valid email address")
        if address.lower() in seen:
            continue
        seen.add(address.lower())
        result.append(formataddr((name.strip(), address)) if name.strip() else address)
    return result, removed


def _clean_body(value: Any) -> tuple[str, int]:
    if value is None:
        return "", 0
    if not isinstance(value, str):
        raise DraftError("body must be text")
    text = unicodedata.normalize("NFC", value).replace("\r\n", "\n").replace("\r", "\n")
    cleaned = _CONTROL.sub("", _INVISIBLE.sub("", text))
    removed = len(text) - len(cleaned)
    cleaned = "\n".join(line.rstrip() for line in cleaned.split("\n")).strip("\n")
    if len(cleaned) > MAX_BODY_CHARS:
        raise DraftError(f"body is longer than {MAX_BODY_CHARS:,} characters")
    return cleaned, removed


def _message_ids(value: Any, what: str, *, many: bool) -> str:
    text, _ = _clean_line(value, what, 4000)
    if not text:
        return ""
    tokens = text.split()
    if not many and len(tokens) != 1:
        raise DraftError(f"{what} must be one message id like <id@host>")
    for token in tokens:
        if not _MESSAGE_ID.match(token):
            raise DraftError(f"{what}: “{token}” is not a message id like <id@host>")
    return " ".join(tokens)


def is_credential_path(path: str) -> bool:
    text = path.replace("\\", "/")
    return bool(_CREDENTIAL_NAMES.search(text) or _CREDENTIAL_DIRS.search(text))


def _read_attachment(raw: str, base_dir: Optional[Path]) -> Attachment:
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = (base_dir or Path.cwd()) / path
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise DraftError(f"attachment not found: {raw}") from exc
    if not resolved.is_file():
        raise DraftError(f"attachment is not a file: {raw}")
    if is_credential_path(str(resolved)) or is_credential_path(str(path)):
        raise DraftError(f"attachment refused: “{resolved.name}” looks like a credential file")
    name, _ = _clean_line(resolved.name, "attachment name", 255)
    hasher = hashlib.sha256()
    size = 0
    try:
        with resolved.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                if size == 0 and _PRIVATE_KEY_BYTES.search(chunk[:8192]):
                    raise DraftError(f"attachment refused: “{resolved.name}” contains a private key")
                size += len(chunk)
                if size > MAX_ATTACHMENT_BYTES:
                    raise DraftError(f"attachment too large: {raw}")
                hasher.update(chunk)
    except OSError as exc:
        raise DraftError(f"attachment cannot be read: {raw}") from exc
    return Attachment(path=str(resolved), name=name, size=size, sha256=hasher.hexdigest())


def build_draft(
    args: dict[str, Any],
    *,
    default_from: str = "",
    base_dir: Optional[Path] = None,
    max_recipients: int = MAX_RECIPIENTS,
) -> Draft:
    """Turn tool arguments into a :class:`Draft`, or raise :class:`DraftError`.

    Only the fields named here exist in a draft. An argument Signet does not know (``bcc``,
    ``reply_to``, ``headers``) is refused, never silently dropped and never passed through.
    """
    if not isinstance(args, dict):
        raise DraftError("arguments must be an object")
    known = {"from", "to", "cc", "subject", "body", "in_reply_to", "references", "attachments"}
    unknown = sorted(key for key, value in args.items() if key not in known and value not in (None, "", [], ()))
    if unknown:
        raise DraftError(
            "unsupported field(s): " + ", ".join(unknown)
            + ". Signet sends From, To, Cc, Subject, body, thread ids and attachments, all shown to the user"
        )
    removed = 0
    senders, count = _parse_addresses(args.get("from") or default_from, "from")
    removed += count
    if len(senders) != 1:
        raise DraftError("from must be exactly one address (or set from_address in the plugin settings)")
    to, count = _parse_addresses(args.get("to"), "to")
    removed += count
    cc, count = _parse_addresses(args.get("cc"), "cc")
    removed += count
    to_addresses = {_address_of(value) for value in to}
    cc = [value for value in cc if _address_of(value) not in to_addresses]
    if not to:
        raise DraftError("to must name at least one recipient")
    if len(to) + len(cc) > max_recipients:
        raise DraftError(f"too many recipients ({len(to) + len(cc)}); the limit is {max_recipients}")
    subject, count = _clean_line(args.get("subject"), "subject", MAX_SUBJECT_CHARS)
    removed += count
    body, count = _clean_body(args.get("body"))
    removed += count
    if not subject and not body:
        raise DraftError("the email has neither a subject nor a body")
    paths = _as_list(args.get("attachments"), "attachments")
    if len(paths) > MAX_ATTACHMENTS:
        raise DraftError(f"too many attachments ({len(paths)}); the limit is {MAX_ATTACHMENTS}")
    attachments = tuple(_read_attachment(path, base_dir) for path in paths)
    if sum(item.size for item in attachments) > MAX_ATTACHMENT_BYTES:
        raise DraftError("attachments are larger than 20 MB in total")
    if len({item.name for item in attachments}) != len(attachments):
        raise DraftError("two attachments have the same file name")
    return Draft(
        sender=senders[0],
        to=tuple(to),
        cc=tuple(cc),
        subject=subject,
        body=body,
        in_reply_to=_message_ids(args.get("in_reply_to"), "in_reply_to", many=False),
        references=_message_ids(args.get("references"), "references", many=True),
        attachments=attachments,
        removed_invisible=removed,
    )


def draft_from_record(record: dict[str, Any]) -> Draft:
    """Rebuild a queued draft exactly as stored, without touching the file system."""
    return Draft(
        sender=str(record["from"]),
        to=tuple(record.get("to") or ()),
        cc=tuple(record.get("cc") or ()),
        subject=str(record.get("subject") or ""),
        body=str(record.get("body") or ""),
        in_reply_to=str(record.get("in_reply_to") or ""),
        references=str(record.get("references") or ""),
        attachments=tuple(
            Attachment(path=str(item["path"]), name=str(item["name"]), size=int(item["size"]), sha256=str(item["sha256"]))
            for item in record.get("attachments") or ()
        ),
    )


def verify_attachments(draft: Draft) -> None:
    """Raise :class:`DraftError` when a file is no longer the one that was fingerprinted."""
    for item in draft.attachments:
        current = _read_attachment(item.path, None)
        if current.sha256 != item.sha256 or current.size != item.size:
            raise DraftError(f"attachment “{item.name}” changed after it was shown for approval")


# --- Notes: what a careful person would want pointed out before sending -------------------------

def _skeleton(domain: str) -> str:
    """Fold the usual look-alike substitutions, so ``examp1e.com`` meets ``example.com``."""
    return domain.lower().replace("0", "o").replace("1", "l").replace("rn", "m").replace("vv", "w")


def _edit_distance(left: str, right: str, limit: int = 2) -> int:
    """Damerau-Levenshtein distance (a swap of two neighbours counts once), capped at ``limit`` + 1."""
    if abs(len(left) - len(right)) > limit:
        return limit + 1
    previous_previous: list[int] = []
    previous = list(range(len(right) + 1))
    for i, a in enumerate(left, 1):
        current = [i]
        for j, b in enumerate(right, 1):
            cost = 0 if a == b else 1
            value = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and a == right[j - 2] and left[i - 2] == b:
                value = min(value, previous_previous[j - 2] + 1)
            current.append(value)
        previous_previous, previous = previous, current
    return previous[-1]


def lookalike_of(domain: str, references: Iterable[str]) -> str:
    """The well-known or already-used domain that ``domain`` imitates, or an empty string."""
    domain = domain.lower()
    candidates = {value.lower() for value in references if value}
    if domain in candidates:
        return ""
    for reference in sorted(candidates):
        if _skeleton(domain) == _skeleton(reference):
            return reference
        if min(len(domain), len(reference)) >= 6 and _edit_distance(domain, reference, 1) <= 1:
            return reference
    return ""


def find_secrets(text: str) -> list[str]:
    return [label for label, pattern in _SECRET_PATTERNS if pattern.search(text or "")]


def link_hosts(text: str) -> tuple[list[str], list[str]]:
    """Hosts of the links in ``text``, and the links that deserve a second look."""
    hosts: list[str] = []
    odd: list[str] = []
    for url in _URL.findall(text or ""):
        try:
            parts = urlsplit(url.rstrip(".,;:!?"))
            host = (parts.hostname or "").lower()
        except ValueError:
            continue
        if not host:
            continue
        if host not in hosts:
            hosts.append(host)
        reason = ""
        if "@" in parts.netloc:
            reason = "hides its real host behind an @"
        elif _IPV4.match(host):
            reason = "points at a bare IP address"
        elif "xn--" in host or not host.isascii():
            reason = "uses an internationalised (look-alike capable) name"
        if reason and f"{host} {reason}" not in odd:
            odd.append(f"{host} {reason}")
    return hosts, odd


def risk_notes(draft: Draft, *, known_addresses: Iterable[str] = (), flag_new: bool = True) -> list[str]:
    """Plain, deterministic observations about a draft. No model is asked; nothing leaves."""
    notes: list[str] = []
    known = {value.lower() for value in known_addresses}
    known_domains = {value.rpartition("@")[2] for value in known}
    reference_domains = known_domains | _COMMON_DOMAINS | {draft.sender_address.rpartition("@")[2]}
    for formatted in (*draft.to, *draft.cc):
        name, address = getaddresses([formatted])[0]
        address = address.lower()
        domain = address.rpartition("@")[2]
        imitated = lookalike_of(domain, reference_domains)
        if imitated:
            notes.append(f"⚠ {address}: the domain looks like {imitated} but is not. Check the spelling.")
        elif domain.startswith("xn--") or ".xn--" in domain:
            notes.append(f"⚠ {address}: internationalised domain, shown here in its real (punycode) form.")
        if flag_new and address not in known:
            notes.append(f"First email to {address} from this agent.")
        shown = _ADDRESS_IN_TEXT.search(name or "")
        if shown and shown.group(0).lower() != address:
            notes.append(f"⚠ The display name shows {shown.group(0)} but the mail goes to {address}.")
    count = len(draft.to) + len(draft.cc)
    if count > 5:
        notes.append(f"{count} recipients.")
    for label in find_secrets(draft.subject + "\n" + draft.body):
        notes.append(f"⚠ The text seems to contain {label}.")
    hosts, odd = link_hosts(draft.body)
    if hosts:
        shown_hosts = ", ".join(hosts[:5]) + (f" and {len(hosts) - 5} more" if len(hosts) > 5 else "")
        notes.append(f"Links to: {shown_hosts}.")
    for item in odd:
        notes.append(f"⚠ A link to {item}.")
    if draft.removed_invisible:
        notes.append(f"{draft.removed_invisible} invisible character(s) were removed from the draft.")
    return notes


# --- The card -----------------------------------------------------------------------------------

def _human_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.0f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def render_card(draft: Draft, notes: Iterable[str] = (), *, preview_chars: int = 900, title: str = "") -> str:
    """The text a person approves. ``preview_chars <= 0`` shows the whole body."""
    lines = [title or "Email waiting for your seal", ""]
    lines.append(f"From:    {draft.sender}")
    lines.append(f"To:      {', '.join(draft.to)}")
    if draft.cc:
        lines.append(f"Cc:      {', '.join(draft.cc)}")
    lines.append(f"Subject: {draft.subject or '(no subject)'}")
    if draft.in_reply_to:
        lines.append(f"Reply to: {draft.in_reply_to}")
    for item in draft.attachments:
        lines.append(f"Attached: {item.name} ({_human_size(item.size)}, sha256 {item.sha256[:12]}…)")
    lines.append("")
    body = draft.body or "(empty body)"
    if preview_chars > 0 and len(body) > preview_chars:
        tail = max(120, preview_chars // 5)
        head = preview_chars - tail
        hidden = len(body) - head - tail
        lines.append(body[:head].rstrip())
        lines.append(f"[… {hidden:,} characters not shown here. Deny, then /signet show {draft.code} to read all …]")
        lines.append(body[-tail:].lstrip())
    else:
        lines.append(body)
    lines.append("")
    notes = list(notes)
    if notes:
        lines.extend(f"• {note}" for note in notes)
        lines.append("")
    lines.append(f"Seal {draft.code} covers exactly this message ({len(draft.body):,} characters). Any change needs a new seal.")
    return "\n".join(lines)


def one_line(draft: Draft) -> str:
    recipients = ", ".join(draft.recipient_addresses[:3]) + (" …" if len(draft.recipient_addresses) > 3 else "")
    return f"{draft.code}  to {recipients}  “{draft.subject or '(no subject)'}”"
