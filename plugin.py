"""Signet's behaviour inside Hermes: the gate, the guard, the two tools and ``/signet``.

How a send works:

1. The model calls ``signet_send_mail``. The ``pre_tool_call`` hook builds the canonical draft,
   holds it in the outbox and escalates the call to Hermes's own approval prompt, with the card
   of that exact draft as the reason.
2. Hermes asks the person on whatever surface they use. ``post_approval_response`` tells Signet
   the answer. Only "once", "session" or "always", given by a person, makes a seal, and a seal
   is tied to the SHA-256 of the draft that was shown.
3. The tool handler rebuilds the draft from the arguments it actually received and sends only
   if a seal exists for that fingerprint. No seal (approvals switched off, YOLO, a scheduled run,
   arguments rewritten after the prompt) means the email stays held, for ``/signet send CODE``.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Optional

from . import guard
from .core import (Draft, DraftError, build_draft, format_code, normalize_code, one_line, record_to_args,
                   render_card, risk_notes, split_mailbox, verify_attachments)
from .schemas import SEND_TOOL
from .store import RULE_PREFIX, Outbox, Seals
from .transport import DEFAULT_COMMAND, TRANSPORTS, deliver

logger = logging.getLogger(__name__)

PLUGIN_ID = "signet"

DEFAULTS: dict[str, Any] = {
    "transport": "outbox",
    "send_command": DEFAULT_COMMAND,
    "send_timeout": 60,
    "smtp_host": "",
    "smtp_port": 0,
    "smtp_security": "starttls",
    "smtp_username": "",
    "from_address": "",
    "allowed_from": [],
    "trusted_recipients": [],
    "guard": "block",
    "cron_guard": "block",
    "max_recipients": 20,
    "preview_chars": 900,
    "seal_header": False,
}

_GUARD_BLOCK = (
    "BLOCKED by Signet: this would send email with {label}, around the user's approval. "
    "Send it with the signet_send_mail tool instead: the user sees the exact message and approves it. "
    "Do not retry this command and do not look for another way to send."
)
_GUARD_TOO_LARGE = (
    "BLOCKED by Signet: this command names a mailer and is too large to inspect. Split it into smaller "
    "commands. To send email, use the signet_send_mail tool: the user sees the exact message and approves it."
)
_GUARD_APPROVE = (
    "This command sends email with {label}, outside Signet: you will not see the message on a card "
    "and nothing checks what leaves. Allow it only if you know exactly what it sends."
)
_HELD = (
    "The email was NOT sent. It is held under code {code}: {reason}. Tell the user they can read it "
    "with /signet show {code} and send it with /signet send {code}. Do not call this tool again for "
    "this email and do not try another way to send it."
)
_NOT_ASKED = "nobody could be asked to approve it (no approval prompt was available)"
_MASKED = "⚠ Hermes masks secret-looking text on this card (***); the real text is what is sent"
_USAGE = (
    "Signet commands:\n"
    "  /signet                 status and the emails waiting for you\n"
    "  /signet show CODE       read a held email in full\n"
    "  /signet send CODE       seal and send a held email (it is shown in full first)\n"
    "  /signet drop CODE       discard a held email\n"
    "  (CODE can be `last`: the email held most recently)\n"
    "  /signet log [N]         the last N ledger entries (default 10)"
)


class Signet:
    def __init__(self, ctx: Any, *, data_dir: Optional[Path] = None) -> None:
        self.ctx = ctx
        self.seals = Seals()
        self._data_dir = Path(data_dir) if data_dir else None

    # --- settings and context --------------------------------------------------------------------
    def setting(self, key: str) -> Any:
        default = DEFAULTS[key]
        try:
            value = self.ctx.get_config(key, default)
        except Exception:  # noqa: BLE001 - a broken settings read must not break the gate
            value = default
        return default if value is None else value

    def _number(self, key: str, low: int, high: int) -> int:
        try:
            return min(high, max(low, int(self.setting(key))))
        except (TypeError, ValueError):
            return int(DEFAULTS[key])

    def _choice(self, key: str, allowed: tuple[str, ...]) -> str:
        value = self.setting(key)
        if value is False:  # YAML reads a bare `off` as false
            value = "off"
        text = str(value).strip().lower()
        return text if text in allowed else str(DEFAULTS[key])

    def _address_set(self, key: str) -> set[str]:
        value = self.setting(key)
        items = [value] if isinstance(value, str) else (value if isinstance(value, (list, tuple)) else [])
        found = set()
        for item in items:
            address = split_mailbox(str(item).strip())[1].strip().lower()
            if address:
                found.add(address)
        return found

    def settings(self) -> dict[str, Any]:
        values = {key: self.setting(key) for key in DEFAULTS}
        values["seal_header"] = values["seal_header"] is True or str(values["seal_header"]).strip().lower() in ("true", "yes", "on", "1")
        return values

    def outbox(self) -> Outbox:
        if self._data_dir is not None:
            return Outbox(self._data_dir)
        from plugins.plugin_storage import plugin_data_dir  # follows the active profile: do not cache
        return Outbox(Path(plugin_data_dir(PLUGIN_ID)))

    def in_cron(self) -> bool:
        probe = getattr(self.ctx, "current_cron_execution", None)
        try:
            return bool(probe and probe() is not None)
        except Exception:  # noqa: BLE001
            return False

    @staticmethod
    def _base_dir() -> Optional[Path]:
        try:
            from agent.runtime_cwd import resolve_agent_cwd
            return Path(resolve_agent_cwd())
        except Exception:  # noqa: BLE001 - outside Hermes, relative paths resolve against the process
            return None

    @staticmethod
    def _secret(name: str) -> Optional[str]:
        try:
            from agent.secret_scope import get_secret
            return get_secret(name)
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _masked_by_hermes(text: str) -> bool:
        """True when Hermes's own redaction would alter this text on an approval surface."""
        try:
            from agent.redact import redact_sensitive_text
            return redact_sensitive_text(text, force=True) != text
        except Exception:  # noqa: BLE001
            return False

    def build(self, args: Any) -> Draft:
        """The draft these arguments make, under the owner's sender rules.

        The agent does not choose who the mail is from: once a sender is configured, a draft may
        only come from it or from an address listed in ``allowed_from``.
        """
        configured = str(self.setting("from_address") or "").strip()
        try:
            draft = build_draft(
                args if isinstance(args, dict) else {},
                default_from=configured,
                base_dir=self._base_dir(),
                max_recipients=self._number("max_recipients", 1, 500),
            )
        except DraftError as exc:
            if configured and str(exc).startswith("from"):
                raise DraftError(f"{exc}. Leave `from` out: the sender is set in the plugin settings") from exc
            raise
        allowed = self._address_set("allowed_from") | self._address_set("from_address")
        if allowed and draft.sender_address not in allowed:
            hint = "leave `from` out to use the configured sender" if configured else "use a sender listed in allowed_from"
            raise DraftError(f"the sender {draft.sender_address} is not one the owner allowed; {hint}")
        return draft

    def needs_no_seal(self, draft: Draft) -> bool:
        """True when every recipient is an address the owner listed as needing no seal."""
        trusted = self._address_set("trusted_recipients")
        return bool(trusted) and all(address in trusted for address in draft.recipient_addresses)

    def card(self, draft: Draft, outbox: Outbox, *, full: bool = False, title: str = "") -> str:
        notes = risk_notes(draft, known_addresses=outbox.known_addresses())
        if not full and self._masked_by_hermes(draft.subject + "\n" + draft.body):
            notes.insert(0, _MASKED)
        preview = 0 if full else self._number("preview_chars", 200, 20000)
        return render_card(draft, notes, preview_chars=preview, title=title)

    # --- hooks -------------------------------------------------------------------------------------
    def pre_tool_call(self, tool_name: str = "", args: Any = None, task_id: str = "", **kwargs: Any) -> Optional[dict[str, Any]]:
        if tool_name == SEND_TOOL:
            return self._gate(args)
        try:
            label = guard.detect(tool_name, args)
            return self._guard(label, tool_name) if label else None
        except Exception:  # noqa: BLE001 - the guard must never break unrelated tool calls
            logger.exception("signet: guard failed on %s", tool_name)
            return None

    def _gate(self, args: Any) -> Optional[dict[str, Any]]:
        """Ask for a person's approval of the draft these arguments make.

        Returning ``None`` never lets mail out: the handler sends only with a seal, and a seal comes
        only from an answered prompt. So when the draft is refused, or anything here fails, there is
        simply no prompt, and the handler reports what is wrong.
        """
        try:
            draft = self.build(args)
            if self.needs_no_seal(draft) or self.in_cron():
                return None  # the handler sends (trusted recipients) or holds (nobody to ask)
            outbox = self.outbox()
            # Held before Hermes decides anything: if no prompt can be shown (no person, no gateway),
            # the draft is not lost. pre_approval_request corrects the reason once a person is asked.
            outbox.hold(draft, _NOT_ASKED)
            return {
                "action": "approve",
                "message": self.card(draft, outbox),
                "rule_key": self.seals.present(draft.digest),
            }
        except DraftError:
            return None
        except Exception:  # noqa: BLE001
            logger.exception("signet: could not prepare the approval prompt")
            return None

    def _guard(self, label: str, tool_name: str) -> Optional[dict[str, Any]]:
        cron = self.in_cron()
        mode = self._choice("cron_guard", ("block", "allow")) if cron else self._choice("guard", ("block", "approve", "off"))
        if mode in ("off", "allow"):
            return None
        if mode == "approve":
            return {"action": "approve", "message": _GUARD_APPROVE.format(label=label), "rule_key": f"signet-guard:{label}"}
        try:
            self.outbox().record("blocked", mailer=label, tool=tool_name, scheduled=cron or None)
        except Exception:  # noqa: BLE001 - the ledger is a record, the block does not depend on it
            logger.exception("signet: could not record a blocked send")
        if label == guard.TOO_LARGE:
            return {"action": "block", "message": _GUARD_TOO_LARGE}
        return {"action": "block", "message": _GUARD_BLOCK.format(label=label)}

    def pre_approval_request(self, pattern_key: str = "", **kwargs: Any) -> None:
        """A person is being asked right now: say so on the held draft."""
        if RULE_PREFIX not in (pattern_key or ""):
            return
        digest = self.seals.digest_for(pattern_key)
        outbox = self.outbox()
        loaded = outbox.load(format_code(digest)) if digest else None
        if loaded is not None and loaded[0].digest == digest:
            outbox.hold(loaded[0], "waiting for your answer to the approval prompt", state="awaiting")

    def post_approval_response(self, pattern_key: str = "", choice: str = "", surface: str = "", **kwargs: Any) -> None:
        if RULE_PREFIX not in (pattern_key or ""):
            return
        digest, sealed = self.seals.resolve(pattern_key, choice, surface)
        if not digest or sealed:
            return
        outbox = self.outbox()
        loaded = outbox.load(format_code(digest))
        if loaded is None or loaded[0].digest != digest:
            return
        draft = loaded[0]
        if choice == "deny":
            # Not sent. Kept one day: a narrow prompt may have shown only the start of the message,
            # and the person can still read it all (/signet show) and send it themselves.
            outbox.hold(draft, "you denied it at the prompt", state="denied", denied_at=time.time())
            outbox.record("denied", draft, surface=surface)
            return
        reason = {
            "timeout": "the approval prompt timed out",
            "cancelled": "the approval prompt was withdrawn before anyone answered",
            "notify_failed": "the approval prompt could not be delivered",
        }.get(choice, f"the approval ended without a person's yes ({choice or 'no answer'})")
        outbox.hold(draft, reason)
        outbox.record("held", draft, reason=reason, surface=surface)

    # --- tools ------------------------------------------------------------------------------------
    def send_mail(self, args: Any, **kwargs: Any) -> str:
        try:
            draft = self.build(args)
            code = draft.code
        except DraftError as exc:
            return _json({"sent": False, "status": "refused", "error": f"Signet refused this draft: {exc}."})
        except Exception as exc:  # noqa: BLE001
            logger.exception("signet: draft failed")
            return _json({"sent": False, "status": "error", "error": f"Signet could not read this draft: {exc}"})
        try:
            seal = self.seals.consume(draft.digest)
            if seal is None and self.needs_no_seal(draft):
                seal = {"by": "policy:trusted_recipients", "surface": ""}
            outbox = self.outbox()
            if seal is None:
                reason = (
                    "this is a scheduled run and nobody was there to approve it" if self.in_cron()
                    else "no approval by a person was recorded for this exact message "
                         "(approvals are switched off, or the message changed after it was shown)"
                )
                outbox.hold(draft, reason)
                outbox.record("held", draft, reason=reason)
                return _json({"sent": False, "status": "held", "code": code,
                              "message": _HELD.format(code=code, reason=reason)})
            if seal.get("by", "").startswith("approval:") and outbox.load(code) is None:
                # The draft was held when the prompt opened. If it is gone, the person has already
                # sent or dropped it with /signet while the prompt was open: one decision, one email.
                return _json({"sent": False, "status": "already_handled", "code": code,
                              "message": "This email was already sent or dropped with /signet while the prompt was open. Nothing more was sent."})
            return _json(self._deliver(draft, seal, outbox))
        except Exception as exc:  # noqa: BLE001
            logger.exception("signet: send failed")
            return _json({"sent": False, "status": "error", "code": code,
                          "error": f"Signet stopped before handing the email to the transport: {exc}. Do not retry; tell the user."})

    def _deliver(self, draft: Draft, seal: dict[str, Any], outbox: Outbox) -> dict[str, Any]:
        delivery = deliver(draft, self.settings(), save=outbox.save_message, secret=self._secret)
        common = {"code": draft.code, "to": draft.recipient_addresses, "subject": draft.subject,
                  "transport": delivery.transport, "detail": delivery.detail}
        if not delivery.ok:
            self._bookkeeping(lambda: outbox.hold(draft, delivery.detail, state="failed"),
                              lambda: outbox.record("failed", draft, sealed_by=seal.get("by"),
                                                    transport=delivery.transport, detail=delivery.detail))
            return {"sent": False, "status": "failed", **common,
                    "message": "The email was not confirmed as sent. Do not retry: a second attempt may deliver it twice. "
                               f"Tell the user what happened; they can retry with /signet send {draft.code}."}
        # The email has left (or was written): whatever happens to the records now, say so.
        complete = self._bookkeeping(
            lambda: outbox.release(draft.code),
            lambda: outbox.record("sent", draft, sealed_by=seal.get("by"), surface=seal.get("surface"),
                                  transport=delivery.transport, message_id=delivery.message_id,
                                  delivered=delivery.delivered))
        result = {"sent": delivery.delivered, "status": "sent" if delivery.delivered else "written", **common,
                  "message_id": delivery.message_id, "sealed_by": seal.get("by")}
        if not delivery.delivered:
            result["message"] = ("Signet's transport is 'outbox': the approved message was written to a file and not "
                                 "delivered. Tell the user to set a transport in the plugin settings.")
        if not complete:
            result["warning"] = "The email went out, but Signet could not update its ledger or outbox. Do not send it again."
        return result

    @staticmethod
    def _bookkeeping(*steps: Any) -> bool:
        complete = True
        for step in steps:
            try:
                step()
            except Exception:  # noqa: BLE001 - a record that cannot be written must not change what is reported
                logger.exception("signet: could not update the outbox or the ledger")
                complete = False
        return complete

    def outbox_tool(self, args: Any, **kwargs: Any) -> str:
        try:
            limit = max(1, min(50, int((args or {}).get("limit") or 10)))
        except (TypeError, ValueError, AttributeError):
            limit = 10
        try:
            outbox = self.outbox()
            held = [{"code": draft.code, "to": draft.recipient_addresses, "subject": draft.subject,
                     "state": record.get("state"), "reason": record.get("reason"),
                     "held_minutes": int(max(0, time.time() - float(record.get("held_at") or 0)) // 60)}
                    for draft, record in outbox.pending()]
            return _json({"held": held, "recent": outbox.entries(limit), "transport": self._choice("transport", TRANSPORTS)})
        except Exception as exc:  # noqa: BLE001
            logger.exception("signet: outbox read failed")
            return _json({"error": f"Signet could not read its outbox: {exc}"})

    # --- /signet ----------------------------------------------------------------------------------
    def command(self, raw_args: str = "", *, platform: str = "", **kwargs: Any) -> str:
        words = (raw_args or "").split()
        verb = words[0].lower() if words else "status"
        argument = words[1] if len(words) > 1 else ""
        try:
            if verb in ("status", "pending", "list"):
                return self._status()
            if verb == "log":
                return self._log(argument)
            if verb in ("show", "send", "drop"):
                return self._on_held(verb, argument, str(platform or ""))
        except Exception as exc:  # noqa: BLE001
            logger.exception("signet: /signet %s failed", verb)
            return f"Signet: /signet {verb} failed: {exc}"
        return _USAGE

    def _status(self) -> str:
        outbox = self.outbox()
        raw_transport = str(self.setting("transport")).strip().lower()
        command = self.setting("send_command")
        shown_command = " ".join(map(str, command)) if isinstance(command, (list, tuple)) else f"{command!r} (must be a list of words)"
        about = {
            "outbox": "outbox (approved emails are written as .eml files, nothing is delivered)",
            "command": f"command ({shown_command})",
            "smtp": f"smtp ({self.setting('smtp_host') or 'smtp_host is not set'})",
        }.get(raw_transport, f"{raw_transport} (unknown: use one of {', '.join(TRANSPORTS)})")
        lines = [f"Signet. Transport: {about}.",
                 f"Guard on direct mailers: {self._choice('guard', ('block', 'approve', 'off'))}; "
                 f"in scheduled runs: {self._choice('cron_guard', ('block', 'allow'))}."]
        sender = str(self.setting("from_address") or "")
        lines.append(f"Default sender: {sender}." if sender else "Default sender: not set (the agent must give one).")
        everything = outbox.pending()
        held = [item for item in everything if item[1].get("state") != "denied"]
        denied = [item for item in everything if item[1].get("state") == "denied"]
        if held:
            lines += ["", f"{len(held)} email(s) waiting for you:"]
            lines += [f"  {one_line(draft)}  ({record.get('reason') or record.get('state')})" for draft, record in held]
        else:
            lines += ["", "No email is waiting for you."]
        if denied:
            lines += ["", "Denied in the last day (not sent, kept in case you want to read or send them):"]
            lines += [f"  {one_line(draft)}" for draft, _ in denied]
        if held or denied:
            lines += ["", "/signet show CODE to read one, /signet send CODE to seal and send it, /signet drop CODE to discard it."]
        sent = [entry for entry in outbox.entries() if entry.get("event") == "sent"][-3:]
        if sent:
            lines += ["", "Last sent:"]
            lines += [f"  {entry.get('at')}  {entry.get('code')}  to {_joined(entry.get('to'))}  “{entry.get('subject') or ''}”"
                      for entry in sent]
        return "\n".join(lines)

    def _log(self, argument: str) -> str:
        try:
            limit = max(1, min(100, int(argument or 10)))
        except ValueError:
            limit = 10
        entries = self.outbox().entries(limit)
        if not entries:
            return "Signet's ledger is empty."
        lines = []
        for entry in entries:
            what = entry.get("code") or entry.get("mailer") or ""
            extra = entry.get("sealed_by") or entry.get("reason") or entry.get("detail") or entry.get("tool") or ""
            subject = f"“{entry.get('subject')}”" if entry.get("subject") else ""
            parts = (str(entry.get("at") or ""), f"{str(entry.get('event') or '?'):<8}", str(what), _joined(entry.get("to")), subject, str(extra))
            lines.append("  ".join(part for part in parts if part))
        return "\n".join(lines)

    def _on_held(self, verb: str, argument: str, platform: str) -> str:
        outbox = self.outbox()
        code = normalize_code(argument)
        if not code and argument.lower() in ("", "last", "latest"):
            # No code typed: the email held most recently, among those still waiting.
            waiting = [draft for draft, record in outbox.pending() if record.get("state") != "denied"]
            if not waiting:
                return "No email is waiting for you. /signet lists the ones you denied."
            code = waiting[-1].code
        if not code:
            return f"Usage: /signet {verb} CODE, or /signet {verb} last (a code looks like 7F3A-91C2; /signet lists them)."
        loaded = outbox.load(code)
        if loaded is None:
            return f"No held email has the code {code}. /signet lists what is waiting."
        draft, record = loaded
        status = record.get("reason") or record.get("state") or ""
        if verb == "show":
            self.seals.mark_shown(draft.digest)
            return self.card(draft, outbox, full=True, title=f"Held email {code} ({status})") + f"\n\n/signet send {code} seals and sends it; /signet drop {code} discards it."
        if verb == "drop":
            self.seals.forget(draft.digest)  # a prompt still open for this draft seals nothing now
            outbox.release(code)
            outbox.record("dropped", draft, surface=platform)
            return f"Dropped {one_line(draft)}. Nothing was sent."
        if self.in_cron():
            return "Signet: a scheduled run cannot seal an email."
        try:
            verify_attachments(draft)
            # A held file is data on disk: it passes the same checks as a fresh draft (sender rules,
            # limits, cleaning) and must come out as the very same message, or it is not sent.
            if self.build(record_to_args(draft.to_record())).digest != draft.digest:
                raise DraftError("the held file is not a draft Signet would have written")
        except DraftError as exc:
            return f"Not sent: {exc}. Ask the agent to prepare the email again."
        if not self.seals.was_shown(draft.digest):
            # A seal covers what its owner has read. Whatever this code points at, show it first.
            self.seals.mark_shown(draft.digest)
            return (self.card(draft, outbox, full=True, title=f"Held email {code} ({status}): this is what would be sent")
                    + f"\n\nNothing was sent yet. If this is right, run /signet send {code} to seal and send it.")
        # Typing the command a second time, after reading it, is the person's seal on this fingerprint.
        self.seals.forget(draft.digest)  # a prompt still open for this draft must not send it twice
        self.seals.seal(draft.digest, by="command:/signet send", surface=platform)
        seal = self.seals.consume(draft.digest)
        if seal is None:
            return f"Not sent: another send of {code} is under way."
        result = self._deliver(draft, seal, outbox)
        if result["status"] == "sent":
            return f"Sent {one_line(draft)} ({result['detail']})."
        if result["status"] == "written":
            return f"Sealed {one_line(draft)}. {result['detail']}. Set a transport in the plugin settings to deliver for real."
        return f"Not sent: {result['detail']}. The email is still held as {code}."


def _joined(value: Any) -> str:
    return ", ".join(str(item) for item in value) if isinstance(value, (list, tuple)) else ""


def _json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False)
