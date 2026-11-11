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
from email import policy as email_policy
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


_ADDRESS = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_MESSAGE_ID = re.compile(r"^<[^<>\s]{1,300}>$")
# An RFC 2047 encoded word: a mail client shows its decoded text, not what is written here.
_ENCODED_WORD = re.compile(r"=\?[^?\s]{1,40}\?[bBqQ]\?[^?\s]*\?=")
_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_ADDRESS_IN_TEXT = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_NAME_NEEDS_QUOTES = re.compile(r"[,;:@()\[\].]")
_MAILBOX = re.compile(r'^(?:"([^"<>]*)"|([^"<>]*?))\s*<([^<>\s]+)>$')

# File names and places that hold credentials. Signet refuses to attach them: a person who really
# wants to mail a key can do it by hand.
_CREDENTIAL_NAMES = re.compile(
    r"(?:^|/)(?:\.env(?:\.[\w.-]+)?|\.netrc|\.pgpass|\.npmrc|\.pypirc|\.git-credentials|auth\.json|token\.json|"
    r"credentials(?:\.json)?|id_(?:rsa|dsa|ecdsa|ed25519)|[\w.-]+\.(?:pem|p8|p12|pfx|keychain|kdbx))$",
    re.IGNORECASE,
)
_CREDENTIAL_DIRS = re.compile(
    r"(?:^|/)(?:\.(?:ssh|aws|gnupg|kube|docker|azure|password-store)|\.config/(?:gh|gcloud|op|himalaya)|secrets)/",
    re.IGNORECASE,
)
_SYSTEM_DIRS = re.compile(r"^/(?:proc|sys|dev)(?:/|$)")
_PRIVATE_KEY_BYTES = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")

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

# --- Characters a reader cannot see ---------------------------------------------------------------
# Written as code points on purpose: this file holds no invisible character itself.
_JOINERS = frozenset({0x200C, 0x200D})            # needed by Persian, Indic scripts and emoji sequences
_EMOJI_SELECTORS = frozenset({0xFE0E, 0xFE0F})    # text / emoji presentation
_BLANK_LETTERS = frozenset({0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x2800, 0x3164, 0xFFA0})
_LINE_BREAKS = dict.fromkeys((0x0B, 0x0C, 0x1C, 0x1D, 0x1E, 0x85, 0x2028, 0x2029), "\n")


def _strip_hidden(text: str) -> tuple[str, int]:
    """Remove what does not show on a card: format and control characters, variation selectors,
    blank "letters". A joiner or an emoji selector stays only where it does its visible job,
    right after a non-ASCII character."""
    kept: list[str] = []
    removed = 0
    for char in text:
        code = ord(char)
        if char in "\n\t" or (0x20 <= code < 0x7F):
            kept.append(char)
            continue
        category = unicodedata.category(char)
        after_wide = bool(kept) and ord(kept[-1]) > 0x7F and ord(kept[-1]) not in _JOINERS
        if category in ("Cc", "Co", "Cs"):
            keep = False
        elif category == "Cf":
            keep = code in _JOINERS and after_wide
        elif code in _EMOJI_SELECTORS:
            keep = after_wide
        elif 0xFE00 <= code <= 0xFE0F or 0xE0100 <= code <= 0xE01EF or code in _BLANK_LETTERS:
            keep = False
        else:
            keep = True
        if keep:
            kept.append(char)
        else:
            removed += 1
    return "".join(kept), removed


def _encodable(value: str, what: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DraftError(f"{what} contains characters that cannot be sent") from exc


@dataclass(frozen=True)
class Attachment:
    path: str
    name: str
    size: int
    sha256: str


@dataclass(frozen=True)
class Draft:
    """One outgoing email in canonical form. Immutable: a change is a new draft, with a new seal.

    ``sender``, ``to`` and ``cc`` hold mailboxes written for a reader, ``Name <address>`` or a
    bare address, exactly as the card prints them.
    """

    sender: str
    to: tuple[str, ...]
    cc: tuple[str, ...]
    subject: str
    body: str
    in_reply_to: str = ""
    attachments: tuple[Attachment, ...] = ()
    removed_invisible: int = 0

    @property
    def sender_address(self) -> str:
        return split_mailbox(self.sender)[1].lower()

    @property
    def recipient_addresses(self) -> list[str]:
        """Lower-cased addresses, for comparing."""
        return [split_mailbox(value)[1].lower() for value in (*self.to, *self.cc)]

    @property
    def envelope_recipients(self) -> list[str]:
        """Addresses as written, for the transport."""
        return [split_mailbox(value)[1] for value in (*self.to, *self.cc)]

    def canonical(self) -> dict[str, Any]:
        return {
            "v": 2,
            "from": self.sender,
            "to": list(self.to),
            "cc": list(self.cc),
            "subject": self.subject,
            "body": self.body,
            "in_reply_to": self.in_reply_to,
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


def format_mailbox(name: str, address: str) -> str:
    if not name:
        return address
    return f'"{name}" <{address}>' if _NAME_NEEDS_QUOTES.search(name) else f"{name} <{address}>"


def split_mailbox(formatted: str) -> tuple[str, str]:
    """``(name, address)`` of a mailbox written by :func:`format_mailbox`."""
    match = _MAILBOX.match(formatted or "")
    if not match:
        return "", (formatted or "").strip()
    return (match.group(1) if match.group(1) is not None else match.group(2)).strip(), match.group(3)


def _clean_line(value: Any, what: str, limit: int) -> tuple[str, int]:
    """One header value: readable text on a single line."""
    if value is None:
        return "", 0
    if not isinstance(value, str):
        raise DraftError(f"{what} must be text")
    _encodable(value, what)
    if len(value.splitlines()) > 1 or value[-1:] in ("\n", "\r"):
        raise DraftError(f"{what} contains a line break, which a mail header cannot hold")
    text = unicodedata.normalize("NFC", value).replace("\t", " ")
    cleaned, removed = _strip_hidden(text)
    cleaned = cleaned.strip()
    if _ENCODED_WORD.search(cleaned):
        raise DraftError(f"{what} contains an encoded word (=?...?=): write it as plain text, so the card shows what the reader will see")
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
    """Validated, de-duplicated mailboxes, each written the way the card shows it."""
    removed = 0
    result: list[str] = []
    seen: set[str] = set()
    for raw in _as_list(value, what):
        cleaned, count = _clean_line(raw, what, 2000)
        removed += count
        if not cleaned:
            continue
        try:
            header = email_policy.default.header_factory("To", cleaned)
            groups = list(header.groups)
            defects = list(header.defects)
            addresses = list(header.addresses)
        except Exception as exc:  # noqa: BLE001 - whatever the parser dislikes is not an address list
            raise DraftError(f"{what}: could not read “{cleaned}” as email addresses") from exc
        if defects or any(group.display_name is not None for group in groups) or not addresses:
            raise DraftError(f"{what}: could not read “{cleaned}” as email addresses (separate them with commas)")
        for parsed in addresses:
            name = " ".join((parsed.display_name or "").replace('"', "").split())
            if "<" in name or ">" in name or _ENCODED_WORD.search(name):
                raise DraftError(f"{what}: the name “{name}” would not show as written")
            try:
                domain = (parsed.domain or "").encode("idna").decode("ascii").lower()
            except UnicodeError as exc:
                raise DraftError(f"{what}: the domain of “{parsed.addr_spec}” is not valid") from exc
            address = f"{parsed.username}@{domain}"
            if not _ADDRESS.match(address):
                raise DraftError(f"{what}: “{parsed.addr_spec or cleaned}” is not a valid email address")
            if address.lower() in seen:
                continue
            seen.add(address.lower())
            result.append(format_mailbox(name, address))
    return result, removed


def _clean_body(value: Any) -> tuple[str, int]:
    if value is None:
        return "", 0
    if not isinstance(value, str):
        raise DraftError("body must be text")
    _encodable(value, "body")
    text = unicodedata.normalize("NFC", value).replace("\r\n", "\n").replace("\r", "\n").translate(_LINE_BREAKS)
    cleaned, removed = _strip_hidden(text)
    cleaned = "\n".join(line.rstrip() for line in cleaned.split("\n")).strip("\n")
    if len(cleaned) > MAX_BODY_CHARS:
        raise DraftError(f"body is longer than {MAX_BODY_CHARS:,} characters")
    return cleaned, removed


def _message_id(value: Any, what: str) -> str:
    text, _ = _clean_line(value, what, 320)
    if text and not _MESSAGE_ID.match(text):
        raise DraftError(f"{what} must be one message id like <id@host>")
    return text


def is_credential_path(path: str) -> bool:
    text = path.replace("\\", "/")
    return bool(_CREDENTIAL_NAMES.search(text) or _CREDENTIAL_DIRS.search(text))


def _read_attachment(raw: str, base_dir: Optional[Path]) -> Attachment:
    try:
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = (base_dir or Path.cwd()) / path
        resolved = path.resolve(strict=True)
    except (OSError, ValueError, RuntimeError) as exc:
        raise DraftError(f"attachment not found: {raw!r}") from exc
    if _SYSTEM_DIRS.match(str(resolved)) or not resolved.is_file():
        raise DraftError(f"attachment is not a regular file: {raw}")
    if is_credential_path(str(resolved)) or is_credential_path(str(path)):
        raise DraftError(f"attachment refused: “{resolved.name}” looks like a credential file")
    # The path and the name are printed on the card: they must be plain, visible text on one line.
    shown, _ = _clean_line(str(resolved), "attachment path", 4096)
    if shown != str(resolved):
        raise DraftError("attachment refused: its path contains invisible or control characters")
    name = resolved.name
    hasher = hashlib.sha256()
    size = 0
    carried = b""  # the end of the previous chunk, so a marker cut in two is still found
    try:
        with resolved.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                if _PRIVATE_KEY_BYTES.search(carried + chunk):
                    raise DraftError(f"attachment refused: “{resolved.name}” contains a private key")
                carried = chunk[-64:]
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
    known = {"from", "to", "cc", "subject", "body", "in_reply_to", "attachments"}
    unknown = sorted(str(key) for key, value in args.items() if key not in known and value not in (None, "", [], ()))
    if unknown:
        raise DraftError(
            "unsupported field(s): " + ", ".join(unknown)
            + ". Signet sends From, To, Cc, Subject, body, the id of the mail being answered and attachments, all shown to the user"
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
    to_addresses = {split_mailbox(value)[1].lower() for value in to}
    cc = [value for value in cc if split_mailbox(value)[1].lower() not in to_addresses]
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
        in_reply_to=_message_id(args.get("in_reply_to"), "in_reply_to"),
        attachments=attachments,
        removed_invisible=removed,
    )


def draft_from_record(record: dict[str, Any]) -> Draft:
    """Rebuild a queued draft exactly as stored, without touching the file system."""
    return Draft(
        sender=str(record["from"]),
        to=tuple(str(value) for value in record.get("to") or ()),
        cc=tuple(str(value) for value in record.get("cc") or ()),
        subject=str(record.get("subject") or ""),
        body=str(record.get("body") or ""),
        in_reply_to=str(record.get("in_reply_to") or ""),
        attachments=tuple(
            Attachment(path=str(item["path"]), name=str(item["name"]), size=int(item["size"]), sha256=str(item["sha256"]))
            for item in record.get("attachments") or ()
        ),
    )


def record_to_args(record: dict[str, Any]) -> dict[str, Any]:
    """The tool arguments that would produce this stored draft, to pass it through build_draft again."""
    return {
        "from": record.get("from"),
        "to": list(record.get("to") or ()),
        "cc": list(record.get("cc") or ()),
        "subject": record.get("subject"),
        "body": record.get("body"),
        "in_reply_to": record.get("in_reply_to"),
        "attachments": [item.get("path") for item in record.get("attachments") or () if isinstance(item, dict)],
    }


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
            reason = "that hides its real host behind an @"
        elif _IPV4.match(host):
            reason = "to a bare IP address"
        elif "xn--" in host or not host.isascii():
            reason = "with an internationalised (look-alike capable) name"
        if reason and f"A link {reason}: {host}" not in odd:
            odd.append(f"A link {reason}: {host}")
    return hosts, odd


def risk_notes(draft: Draft, *, known_addresses: Iterable[str] = ()) -> list[str]:
    """Plain, deterministic observations about a draft. No model is asked; nothing leaves.

    Warnings start with ``⚠`` and are short: the card shows them right under the recipients, where
    the narrowest approval prompt still has room for them.
    """
    notes: list[str] = []
    known = {value.lower() for value in known_addresses}
    known_domains = {value.rpartition("@")[2] for value in known}
    reference_domains = known_domains | _COMMON_DOMAINS | {draft.sender_address.rpartition("@")[2]}
    new: list[str] = []
    for formatted in (*draft.to, *draft.cc):
        name, address = split_mailbox(formatted)
        address = address.lower()
        domain = address.rpartition("@")[2]
        imitated = lookalike_of(domain, reference_domains)
        if imitated:
            notes.append(f"⚠ {address}: looks like {imitated} but is not")
        elif domain.startswith("xn--") or ".xn--" in domain:
            notes.append(f"⚠ {address}: internationalised domain, shown in its real (punycode) form")
        if address not in known:
            new.append(address)
        shown = _ADDRESS_IN_TEXT.search(name or "")
        if shown and shown.group(0).lower() != address:
            notes.append(f"⚠ The name shows {shown.group(0)} but the mail goes to {address}")
    for label in find_secrets(draft.subject + "\n" + draft.body):
        notes.append(f"⚠ The text seems to contain {label}")
    hosts, odd = link_hosts(draft.body)
    notes.extend(f"⚠ {item}" for item in odd)
    if new:
        more = f" (+{len(new) - 3} more)" if len(new) > 3 else ""
        notes.append(f"New recipient{'s' if len(new) > 1 else ''}: {', '.join(new[:3])}{more}")
    count = len(draft.to) + len(draft.cc)
    if count > 5:
        notes.append(f"{count} recipients")
    if hosts:
        notes.append("Links: " + ", ".join(hosts[:4]) + (f" (+{len(hosts) - 4} more)" if len(hosts) > 4 else ""))
    if draft.removed_invisible:
        notes.append(f"{draft.removed_invisible} invisible character(s) removed from the draft")
    return notes


# --- The card -----------------------------------------------------------------------------------

# The classic Hermes CLI shows at most ten rows of an approval reason, about sixty columns wide,
# and cuts the rest. The card is therefore ordered by what must not be missed: the seal code,
# the recipients, the warnings, then sender, subject, and the text.
_PROMPT_ROWS = 10
_PROMPT_COLUMNS = 58
BODY_MARK = "│ "  # every line of the email's own text carries it, so the text cannot pose as a card line


def _human_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.0f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def _rows(lines: Iterable[str]) -> int:
    return sum(max(1, -(-len(part) // _PROMPT_COLUMNS)) for line in lines for part in line.split("\n"))


def _quote(text: str) -> list[str]:
    return [f"{BODY_MARK}{line}".rstrip() for line in text.split("\n")]


def render_card(draft: Draft, notes: Iterable[str] = (), *, preview_chars: int = 900, title: str = "") -> str:
    """The text a person approves. ``preview_chars <= 0`` shows the whole body (``/signet show``)."""
    notes = list(notes)
    warnings = [note for note in notes if note.startswith("⚠")]
    remarks = [note for note in notes if not note.startswith("⚠")]
    head = [f"To:      {', '.join(draft.to)}"]
    if draft.cc:
        head.append(f"Cc:      {', '.join(draft.cc)}")
    head.extend(warnings)
    head.append(f"From:    {draft.sender}")
    head.append(f"Subject: {draft.subject or '(no subject)'}")
    if draft.in_reply_to:
        head.append(f"Answers: {draft.in_reply_to}")
    for item in draft.attachments:
        head.append(f"Attached: {item.name} ({_human_size(item.size)}, sha256 {item.sha256[:12]}…)")
        head.append(f"          from {item.path}")
    head.extend(remarks)
    body = draft.body or "(empty body)"
    text = _quote(body)
    if preview_chars > 0 and len(body) > preview_chars:
        tail = max(120, preview_chars // 5)
        cut = preview_chars - tail
        text = [*_quote(body[:cut].rstrip()),
                f"[… {len(body) - cut - tail:,} characters not shown: deny, then /signet show {draft.code} …]",
                *_quote(body[-tail:].lstrip())]
    lines = [title or f"Seal {draft.code}: approve to send exactly this email"]
    if preview_chars > 0 and _rows([*lines, *head, *text]) > _PROMPT_ROWS:
        lines.append(f"If it is cut off below: deny, then /signet show {draft.code}")
    lines.extend(head)
    lines.extend(text)
    lines.append(f"Seal {draft.code} covers exactly this message ({len(draft.body):,} characters). Any change needs a new seal.")
    return "\n".join(lines)


def one_line(draft: Draft) -> str:
    recipients = ", ".join(draft.recipient_addresses[:3]) + (" …" if len(draft.recipient_addresses) > 3 else "")
    return f"{draft.code}  to {recipients}  “{draft.subject or '(no subject)'}”"
