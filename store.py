"""Seals, the outbox of drafts waiting for a person, and the ledger.

Seals live in the memory of the Hermes process and nowhere else: nothing an agent can write to
disk turns into one. The outbox and the ledger are files under the plugin's data directory; the
ledger is a record for people and is never read back as a permission.
"""
from __future__ import annotations

import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Optional

from .core import Draft, draft_from_record, normalize_code

RULE_PREFIX = "signet:"
HUMAN_CHOICES = frozenset({"once", "session", "always"})
_PRESENTED_TTL = 24 * 3600
_SEAL_TTL = 300
_MAX_TRACKED = 500
DENIED_KEPT = 24 * 3600
MAX_HELD = 200
INTERRUPTED_AFTER = 600
_SHOWN_TTL = 3600
_LEDGER_TAIL = 5000
_FILES = threading.Lock()  # one lock for the files of every profile served by this process


class Seals:
    """Which exact drafts a person has approved, each usable once."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._presented: dict[str, tuple[str, float]] = {}  # rule key -> (digest, shown at)
        self._sealed: dict[str, dict[str, Any]] = {}         # digest -> seal
        self._shown: dict[str, float] = {}                   # digest -> shown in full at

    def present(self, digest: str) -> str:
        """Register that ``digest`` is about to be shown, and return the rule key of that showing.

        The key is new every time, so an "always allow" answer can never cover a later message.
        """
        rule_key = f"{RULE_PREFIX}{digest[:16]}:{secrets.token_hex(4)}"
        now = time.time()
        with self._lock:
            self._prune(now)
            self._presented[rule_key] = (digest, now)
        return rule_key

    def digest_for(self, pattern_key: str) -> str:
        """The digest shown under an approval ``pattern_key``, or an empty string."""
        rule_key = _rule_key(pattern_key)
        with self._lock:
            entry = self._presented.get(rule_key)
        return entry[0] if entry else ""

    def resolve(self, pattern_key: str, choice: str, surface: str = "") -> tuple[str, bool]:
        """Record the answer to a showing. Returns ``(digest, sealed)``; digest is empty when unknown."""
        rule_key = _rule_key(pattern_key)
        now = time.time()
        with self._lock:
            entry = self._presented.pop(rule_key, None)
            if entry is None:
                return "", False
            digest = entry[0]
            if choice in HUMAN_CHOICES:
                self._sealed[digest] = {"at": now, "by": f"approval:{choice}", "surface": surface}
                return digest, True
        return digest, False

    def seal(self, digest: str, by: str, surface: str = "") -> None:
        with self._lock:
            self._sealed[digest] = {"at": time.time(), "by": by, "surface": surface}

    def mark_shown(self, digest: str) -> None:
        """A trusted surface has just displayed this draft in full to a person."""
        with self._lock:
            self._shown[digest] = time.time()

    def was_shown(self, digest: str) -> bool:
        with self._lock:
            at = self._shown.get(digest)
        return at is not None and time.time() - at <= _SHOWN_TTL

    def forget(self, digest: str) -> None:
        """Void every open showing and unused seal of ``digest``: a prompt answered later seals nothing."""
        with self._lock:
            for key in [key for key, (shown, _) in self._presented.items() if shown == digest]:
                del self._presented[key]
            self._sealed.pop(digest, None)
            self._shown.pop(digest, None)

    def consume(self, digest: str) -> Optional[dict[str, Any]]:
        """Take the seal of ``digest``. A seal is spent by the first send that uses it."""
        now = time.time()
        with self._lock:
            seal = self._sealed.pop(digest, None)
        if seal is None or now - seal["at"] > _SEAL_TTL:
            return None
        return seal

    def _prune(self, now: float) -> None:
        for key in [key for key, (_, at) in self._presented.items() if now - at > _PRESENTED_TTL]:
            del self._presented[key]
        while len(self._presented) > _MAX_TRACKED:
            del self._presented[next(iter(self._presented))]
        for key in [key for key, seal in self._sealed.items() if now - seal["at"] > _SEAL_TTL]:
            del self._sealed[key]
        for key in [key for key, at in self._shown.items() if now - at > _SHOWN_TTL]:
            del self._shown[key]


def _rule_key(pattern_key: str) -> str:
    """Hermes reports a plugin rule as ``plugin_rule:<rule key>``."""
    text = pattern_key or ""
    return text.split("plugin_rule:", 1)[1] if text.startswith("plugin_rule:") else text


class Outbox:
    """Drafts on disk, waiting for a person, plus the append-only ledger."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._lock = _FILES

    # --- paths ---------------------------------------------------------------------------------
    def _dir(self, name: str) -> Path:
        path = self.root / name
        path.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
        return path

    def _pending_path(self, code: str) -> Path:
        return self._dir("pending") / f"{code}.json"

    @property
    def ledger_path(self) -> Path:
        return self.root / "ledger.jsonl"

    # --- pending drafts ------------------------------------------------------------------------
    def hold(self, draft: Draft, reason: str, *, state: str = "pending", **extra: Any) -> None:
        """Keep ``draft`` for a person to review. Re-holding the same draft updates its reason."""
        record = {
            "code": draft.code,
            "digest": draft.digest,
            "state": state,
            "reason": reason,
            "held_at": time.time(),
            "draft": draft.to_record(),
            **extra,
        }
        path = self._pending_path(draft.code)
        with self._lock:
            try:
                earlier = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(earlier, dict) and earlier.get("digest") == draft.digest:
                    record["held_at"] = float(earlier.get("held_at") or record["held_at"])
            except Exception:  # noqa: BLE001 - no file yet, or one that is not ours: start afresh
                pass
            _write_private(path, json.dumps(record, ensure_ascii=False, indent=1))
            self._trim()

    def load(self, code: str) -> Optional[tuple[Draft, dict[str, Any]]]:
        """The held draft with this code, checked against its own fingerprint."""
        code = normalize_code(code)
        if not code:
            return None
        path = self._pending_path(code)
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            draft = draft_from_record(record["draft"])
            # A file edited after it was written no longer matches its name: treat it as absent.
            if draft.code != code or draft.digest != record.get("digest"):
                return None
        except Exception:  # noqa: BLE001 - a damaged or foreign file is simply not a held draft
            return None
        return draft, record

    def _trim(self) -> None:
        """Keep the newest MAX_HELD drafts: an agent in a loop must not fill the disk."""
        files = sorted(self._dir("pending").glob("*.json"), key=lambda item: item.stat().st_mtime)
        for path in files[:-MAX_HELD] if len(files) > MAX_HELD else ():
            try:
                path.unlink()
            except OSError:
                pass

    def claim(self, code: str) -> bool:
        """Take the held draft for sending. Only one caller, in any process, gets ``True``:
        the file is renamed, and a rename succeeds once."""
        code = normalize_code(code)
        if not code:
            return False
        try:
            os.rename(self._pending_path(code), self._dir("sending") / f"{code}.json")
        except OSError:
            return False
        return True

    def settle(self, code: str) -> None:
        """Forget a claim once the send has ended, whatever its outcome."""
        code = normalize_code(code)
        if code:
            try:
                (self._dir("sending") / f"{code}.json").unlink()
            except OSError:
                pass

    def _recover_interrupted(self, now: float) -> None:
        """A claim older than ten minutes belongs to a send that died: give the draft back, marked."""
        for path in self._dir("sending").glob("*.json"):
            try:
                if now - path.stat().st_mtime < INTERRUPTED_AFTER:
                    continue
                record = json.loads(path.read_text(encoding="utf-8"))
                record.update(state="failed", reason="a send was interrupted: this email may or may not have left")
                _write_private(self._pending_path(path.stem), json.dumps(record, ensure_ascii=False, indent=1))
                path.unlink()
            except Exception:  # noqa: BLE001 - a damaged claim is left where it is
                continue

    def release(self, code: str) -> None:
        code = normalize_code(code)
        if code:
            with self._lock:
                try:
                    self._pending_path(code).unlink()
                except OSError:
                    pass

    def pending(self) -> list[tuple[Draft, dict[str, Any]]]:
        """Every held draft, oldest first. A draft the person denied is kept one day, then removed."""
        items = []
        now = time.time()
        self._recover_interrupted(now)
        for path in sorted(self._dir("pending").glob("*.json")):
            loaded = self.load(path.stem)
            if not loaded:
                continue
            record = loaded[1]
            if record.get("state") == "denied" and now - float(record.get("denied_at") or 0) > DENIED_KEPT:
                self.release(path.stem)
                continue
            items.append(loaded)
        items.sort(key=lambda item: item[1].get("held_at", 0))
        return items

    # --- ledger --------------------------------------------------------------------------------
    def record(self, event: str, draft: Optional[Draft] = None, **fields: Any) -> None:
        entry: dict[str, Any] = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event}
        if draft is not None:
            entry.update({
                "code": draft.code,
                "digest": draft.digest,
                "from": draft.sender_address,
                "to": [value for value in draft.recipient_addresses],
                "subject": draft.subject,
                "attachments": [item.name for item in draft.attachments],
            })
        entry.update({key: value for key, value in fields.items() if value not in (None, "")})
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        self.root.mkdir(parents=True, exist_ok=True)
        with self._lock:
            descriptor = os.open(self.ledger_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(descriptor, line.encode("utf-8"))
            finally:
                os.close(descriptor)

    def entries(self, limit: int = 0) -> list[dict[str, Any]]:
        try:
            lines = self.ledger_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        entries = []
        for line in lines[-(limit or _LEDGER_TAIL):]:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict):
                entries.append(entry)
        return entries

    def known_addresses(self) -> set[str]:
        """Addresses this agent has already written to, for the "first email to" note only."""
        known: set[str] = set()
        for entry in self.entries():
            if entry.get("event") == "sent":
                known.update(str(value).lower() for value in entry.get("to") or ())
        return known

    def save_message(self, draft: Draft, data: bytes) -> Path:
        path = self._dir("outbox") / f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{draft.code}.eml"
        _write_private(path, data)
        return path


def _write_private(path: Path, data: Any) -> None:
    payload = data if isinstance(data, bytes) else str(data).encode("utf-8")
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
