"""The gate, the seal and the outbox, driven the way Hermes drives them."""
import json
import shutil
import sys
import tempfile
import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path

from helpers import FakeContext, SmtpSink, load, module

plugin = module("plugin")
schemas = module("schemas")

MAIL = {"from": "Ada <ada@example.org>", "to": ["bob@example.com"], "subject": "Q3 figures", "body": "Hi Bob,\nfigures attached.\n"}


class Harness(unittest.TestCase):
    def setUp(self):
        self.data = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.data, ignore_errors=True))
        self.ctx = FakeContext()
        self.signet = plugin.Signet(self.ctx, data_dir=self.data)

    # What Hermes does around a tool call, reduced to the parts Signet sees.
    def call(self, args, answer="once", *, gate_open=False, handler_args=None):
        """Run pre_tool_call, the person's ``answer`` and the handler. Returns (directive, result)."""
        directive = self.signet.pre_tool_call(tool_name=schemas.SEND_TOOL, args=args, task_id="t")
        if directive and directive.get("action") == "approve" and not gate_open:
            self.signet.pre_approval_request(pattern_key=f"plugin_rule:{directive['rule_key']}", surface="cli")
            self.signet.post_approval_response(
                pattern_key=f"plugin_rule:{directive['rule_key']}", choice=answer, surface="cli",
                command="<signet_send_mail> (plugin approval rule)", description=directive["message"])
            if answer not in ("once", "session", "always"):
                return directive, None  # Hermes does not run the handler
        return directive, json.loads(self.signet.send_mail(handler_args if handler_args is not None else args))

    def eml(self):
        return sorted((self.data / "outbox").glob("*.eml")) if (self.data / "outbox").exists() else []

    def events(self):
        return [entry["event"] for entry in self.signet.outbox().entries()]

    def held(self):
        return [draft.code for draft, _ in self.signet.outbox().pending()]


class Sealing(Harness):
    def test_a_yes_sends_exactly_what_was_shown(self):
        directive, result = self.call(MAIL)
        self.assertEqual(directive["action"], "approve")
        for shown in ("Ada <ada@example.org>", "bob@example.com", "Q3 figures", "figures attached."):
            self.assertIn(shown, directive["message"])
        self.assertEqual(result["status"], "written")
        self.assertEqual(result["sealed_by"], "approval:once")
        message = BytesParser(policy=policy.default).parsebytes(self.eml()[0].read_bytes())
        self.assertEqual(message["To"], "bob@example.com")
        self.assertEqual(message["Subject"], "Q3 figures")
        self.assertEqual(message.get_content().replace("\r\n", "\n").strip(), MAIL["body"].strip())
        self.assertIsNone(message["Bcc"])
        self.assertEqual(self.events(), ["sent"])
        self.assertEqual(self.held(), [])

    def test_a_seal_is_spent_by_one_send(self):
        self.call(MAIL)
        again = json.loads(self.signet.send_mail(MAIL))
        self.assertEqual(again["status"], "held")
        self.assertEqual(len(self.eml()), 1)

    def test_each_showing_has_its_own_rule_key(self):
        first = self.signet.pre_tool_call(tool_name=schemas.SEND_TOOL, args=MAIL)
        second = self.signet.pre_tool_call(tool_name=schemas.SEND_TOOL, args=MAIL)
        self.assertNotEqual(first["rule_key"], second["rule_key"])

    def test_arguments_changed_after_the_prompt_are_not_covered(self):
        tampered = {**MAIL, "to": ["bob@example.com", "eve@evil.example"]}
        _, result = self.call(MAIL, handler_args=tampered)
        self.assertEqual(result["status"], "held")
        self.assertEqual(self.eml(), [])
        body = {**MAIL, "body": MAIL["body"] + "PS: wire the money today."}
        _, result = self.call(MAIL, handler_args=body)
        self.assertEqual(result["status"], "held")
        self.assertEqual(self.eml(), [])

    def test_a_no_sends_nothing(self):
        directive, result = self.call(MAIL, answer="deny")
        self.assertIsNone(result)
        self.assertEqual(self.eml(), [])
        self.assertEqual(self.events(), ["denied"])
        # Even if the handler ran, a denied draft has no seal.
        self.assertEqual(json.loads(self.signet.send_mail(MAIL))["status"], "held")
        self.assertEqual(self.eml(), [])

    def test_a_denied_email_is_kept_one_day_for_the_person_only(self):
        self.call(MAIL, answer="deny")
        code = self.signet.build(MAIL).code
        status = self.signet.command("")
        self.assertIn("No email is waiting", status)
        self.assertIn("Denied in the last day", status)
        self.assertIn(code, status)
        self.assertIn("figures attached.", self.signet.command(f"show {code}"))
        path = self.data / "pending" / f"{code}.json"
        record = json.loads(path.read_text())
        record["denied_at"] -= 25 * 3600
        path.write_text(json.dumps(record))
        self.assertNotIn(code, self.signet.command(""))
        self.assertFalse(path.exists())

    def test_silence_is_not_a_yes(self):
        for answer in ("timeout", "cancelled", "notify_failed", "smart_approve"):
            with self.subTest(answer=answer):
                self.call({**MAIL, "subject": answer}, answer=answer)
                self.assertEqual(self.eml(), [])
        self.assertEqual(len(self.held()), 4)
        # Even if Hermes then ran the handler, there is no seal to find.
        self.assertEqual(json.loads(self.signet.send_mail({**MAIL, "subject": "smart_approve"}))["status"], "held")

    def test_a_bypassed_gate_cannot_seal(self):
        """YOLO or approvals.mode off: Hermes approves without asking, so no hook fires."""
        directive, result = self.call(MAIL, gate_open=True)
        self.assertEqual(directive["action"], "approve")
        self.assertEqual(result["status"], "held")
        self.assertFalse(result["sent"])
        self.assertIn("/signet send", result["message"])
        self.assertEqual(self.eml(), [])
        self.assertEqual(len(self.held()), 1)

    def test_a_draft_nobody_was_asked_about_says_so(self):
        """Hermes blocks fail-closed when there is no person and no gateway: no hook fires at all."""
        self.signet.pre_tool_call(tool_name=schemas.SEND_TOOL, args=MAIL)
        (draft, record), = self.signet.outbox().pending()
        self.assertIn("nobody could be asked", record["reason"])
        self.assertEqual(self.eml(), [])

    def test_a_draft_being_shown_says_so(self):
        directive = self.signet.pre_tool_call(tool_name=schemas.SEND_TOOL, args=MAIL)
        self.signet.pre_approval_request(pattern_key=f"plugin_rule:{directive['rule_key']}")
        (draft, record), = self.signet.outbox().pending()
        self.assertEqual(record["state"], "awaiting")

    def test_an_answer_for_another_plugin_is_ignored(self):
        self.signet.post_approval_response(pattern_key="plugin_rule:other:abc", choice="once")
        self.signet.post_approval_response(pattern_key="rm_rf", choice="always")
        self.assertEqual(json.loads(self.signet.send_mail(MAIL))["status"], "held")

    def test_a_forged_rule_key_seals_nothing(self):
        digest = self.signet.build(MAIL).digest
        self.signet.post_approval_response(pattern_key=f"plugin_rule:signet:{digest[:16]}:deadbeef", choice="once")
        self.assertEqual(json.loads(self.signet.send_mail(MAIL))["status"], "held")

    def test_a_bad_draft_is_explained_without_a_prompt(self):
        directive, result = self.call({**MAIL, "bcc": ["eve@evil.example"]})
        self.assertIsNone(directive)
        self.assertEqual(result["status"], "refused")
        self.assertIn("bcc", result["error"])


class Policies(Harness):
    def test_scheduled_runs_hold_instead_of_asking(self):
        self.ctx.cron = object()
        directive, result = self.call(MAIL)
        self.assertIsNone(directive)
        self.assertEqual(result["status"], "held")
        self.assertIn("scheduled run", result["message"])
        self.assertEqual(self.eml(), [])

    def test_trusted_recipients_need_no_seal_even_in_a_scheduled_run(self):
        self.ctx.settings["trusted_recipients"] = ["Bob@Example.com"]
        self.ctx.cron = object()
        directive, result = self.call(MAIL)
        self.assertIsNone(directive)
        self.assertEqual(result["sealed_by"], "policy:trusted_recipients")
        self.assertEqual(len(self.eml()), 1)

    def test_one_untrusted_recipient_brings_the_prompt_back(self):
        self.ctx.settings["trusted_recipients"] = ["bob@example.com"]
        directive, _ = self.call({**MAIL, "cc": ["carol@example.com"]})
        self.assertEqual(directive["action"], "approve")

    def test_allowed_senders(self):
        self.ctx.settings["allowed_from"] = ["me@example.org"]
        _, result = self.call(MAIL)
        self.assertEqual(result["status"], "refused")
        self.assertIn("allowed_from", result["error"])

    def test_the_agent_does_not_choose_the_sender(self):
        self.ctx.settings["from_address"] = "Ada <ada@example.org>"
        directive, result = self.call({**MAIL, "from": "Ada <ada@example.com>"})  # an invented look-alike
        self.assertIsNone(directive)
        self.assertEqual(result["status"], "refused")
        self.assertIn("leave `from` out", result["error"])
        _, result = self.call({**MAIL, "from": "Ada"})  # a name, as a model writes after "sign as Ada"
        self.assertIn("Leave `from` out", result["error"])
        _, result = self.call({**MAIL, "from": "ADA@example.org"})  # the configured address itself is fine
        self.assertEqual(result["status"], "written")
        self.ctx.settings["allowed_from"] = ["team@example.org"]
        _, result = self.call({**MAIL, "from": "team@example.org", "subject": "other"})
        self.assertEqual(result["status"], "written")

    def test_default_sender(self):
        self.ctx.settings["from_address"] = "Me <me@example.org>"
        mail = {key: value for key, value in MAIL.items() if key != "from"}
        directive, result = self.call(mail)
        self.assertIn("Me <me@example.org>", directive["message"])
        self.assertEqual(result["status"], "written")


class Settings(Harness):
    def test_nonsense_settings_fall_back_instead_of_breaking_the_gate(self):
        self.ctx.settings.update(max_recipients="abc", preview_chars=[1], send_timeout="soon", send_command=5,
                                 smtp_port="x", allowed_from=7, trusted_recipients={"a": 1}, seal_header="false")
        directive, result = self.call(MAIL)
        self.assertEqual(directive["action"], "approve")
        self.assertEqual(result["status"], "written")
        self.assertNotIn("X-Signet-Seal", self.eml()[0].read_text())
        self.assertIn("Transport: outbox", self.signet.command(""))
        self.ctx.settings["transport"] = "command"
        self.assertIn("must be a list of words", self.signet.command(""))
        self.ctx.settings.update(transport="smtp", smtp_host="127.0.0.1", smtp_security="none")
        _, result = self.call({**MAIL, "subject": "again"})
        self.assertEqual(result["status"], "failed")
        self.assertIn("smtp_port must be a number", result["detail"])

    def test_yaml_off_switches_the_guard_off(self):
        self.ctx.settings["guard"] = False
        self.assertIsNone(self.signet.pre_tool_call(tool_name="terminal", args={"command": "msmtp -t < m"}))
        self.ctx.settings["guard"] = "nonsense"
        self.assertEqual(self.signet.pre_tool_call(tool_name="terminal", args={"command": "msmtp -t < m"})["action"], "block")

    def test_trusted_and_allowed_lists_accept_names_around_addresses(self):
        self.ctx.settings.update(trusted_recipients=["Bob <BOB@example.com>"], allowed_from="Ada <ada@example.org>")
        directive, result = self.call(MAIL)
        self.assertIsNone(directive)
        self.assertEqual(result["sealed_by"], "policy:trusted_recipients")

    def test_a_ledger_that_cannot_be_written_does_not_hide_a_send(self):
        self.data.mkdir(exist_ok=True)
        (self.data / "ledger.jsonl").mkdir()  # a folder where the ledger file should be
        directive = self.signet.pre_tool_call(tool_name=schemas.SEND_TOOL, args=MAIL)
        self.signet.post_approval_response(pattern_key=f"plugin_rule:{directive['rule_key']}", choice="once")
        with self.assertLogs(plugin.logger, level="ERROR"):
            result = json.loads(self.signet.send_mail(MAIL))
        self.assertEqual(result["status"], "written")
        self.assertIn("Do not send it again", result["warning"])
        self.assertEqual(len(self.eml()), 1)

    def test_a_hook_never_raises_whatever_it_is_given(self):
        for args in (None, "text", 42, [], {"to": 5}, {"to": ["x" + chr(0xD800) + "@example.com"], "subject": "s", "body": "b"},
                     {**MAIL, "attachments": ["bad\x00name"]}, {**MAIL, "attachments": ["~no-such-user-xyz/f"]}):
            with self.subTest(args=args):
                self.assertIsNone(self.signet.pre_tool_call(tool_name=schemas.SEND_TOOL, args=args))
                self.assertIn(json.loads(self.signet.send_mail(args))["status"], ("refused", "error"))
        for tool in ("terminal", "execute_code", "read_file", ""):
            for args in (None, "text", 42, {"command": None}, {"command": ["a"]}, {"code": 3.5}):
                self.assertIsNone(self.signet.pre_tool_call(tool_name=tool, args=args))
        self.signet.pre_approval_request()
        self.signet.pre_approval_request(pattern_key=None)
        self.signet.post_approval_response()
        self.signet.post_approval_response(pattern_key="plugin_rule:signet:zz", choice=None)
        self.assertIn("Signet.", self.signet.command(None))
        self.assertIn("held", json.loads(self.signet.outbox_tool("not an object")))


class Guarding(Harness):
    SEND = {"command": "cat mail.eml | himalaya message send"}

    def test_direct_mailers_are_blocked_and_recorded(self):
        directive = self.signet.pre_tool_call(tool_name="terminal", args=self.SEND)
        self.assertEqual(directive["action"], "block")
        self.assertIn("signet_send_mail", directive["message"])
        entry = self.signet.outbox().entries()[-1]
        self.assertEqual((entry["event"], entry["mailer"], entry["tool"]), ("blocked", "himalaya send", "terminal"))
        self.assertNotIn("mail.eml", json.dumps(entry))  # the command itself is never stored

    def test_a_mailer_buried_in_a_huge_command_is_blocked_with_its_own_message(self):
        directive = self.signet.pre_tool_call(tool_name="terminal", args={"command": "echo padding\n" * 40_000 + "msmtp -t < m"})
        self.assertEqual(directive["action"], "block")
        self.assertIn("too large to inspect", directive["message"])

    def test_ordinary_commands_pass(self):
        self.assertIsNone(self.signet.pre_tool_call(tool_name="terminal", args={"command": "ls -la"}))
        self.assertIsNone(self.signet.pre_tool_call(tool_name="read_file", args={"path": "x"}))

    def test_guard_modes(self):
        self.ctx.settings["guard"] = "approve"
        self.assertEqual(self.signet.pre_tool_call(tool_name="terminal", args=self.SEND)["action"], "approve")
        self.ctx.settings["guard"] = "off"
        self.assertIsNone(self.signet.pre_tool_call(tool_name="terminal", args=self.SEND))

    def test_scheduled_runs_follow_cron_guard(self):
        self.ctx.cron = object()
        self.ctx.settings["guard"] = "off"
        self.assertEqual(self.signet.pre_tool_call(tool_name="terminal", args=self.SEND)["action"], "block")
        self.ctx.settings["cron_guard"] = "allow"
        self.assertIsNone(self.signet.pre_tool_call(tool_name="terminal", args=self.SEND))

    def test_a_guard_approval_is_not_a_seal(self):
        self.ctx.settings["guard"] = "approve"
        directive = self.signet.pre_tool_call(tool_name="terminal", args=self.SEND)
        self.signet.post_approval_response(pattern_key=f"plugin_rule:{directive['rule_key']}", choice="always")
        self.assertEqual(json.loads(self.signet.send_mail(MAIL))["status"], "held")


class Command(Harness):
    def hold_one(self):
        _, result = self.call(MAIL, gate_open=True)
        return result["code"]

    def test_status_lists_what_waits(self):
        self.assertIn("No email is waiting", self.signet.command(""))
        code = self.hold_one()
        status = self.signet.command("")
        self.assertIn(code, status)
        self.assertIn("bob@example.com", status)

    def test_show_gives_the_whole_message(self):
        long = {**MAIL, "body": "START " + "x" * 3000 + " END"}
        _, result = self.call(long, gate_open=True)
        shown = self.signet.command(f"show {result['code']}")
        self.assertIn("x" * 3000, shown)
        self.assertNotIn("not shown", shown)

    def test_send_shows_the_whole_email_first_and_seals_on_the_second_call(self):
        long = {**MAIL, "body": "START " + "x" * 3000 + " END"}
        _, result = self.call(long, gate_open=True)
        code = result["code"]
        first = self.signet.command(f"send {code.lower().replace('-', '')}", platform="cli")
        self.assertIn("x" * 3000, first)
        self.assertIn("Nothing was sent yet", first)
        self.assertEqual(self.eml(), [])
        second = self.signet.command(f"send {code}", platform="cli")
        self.assertIn("Sealed", second)
        self.assertEqual(len(self.eml()), 1)
        self.assertEqual(self.held(), [])
        self.assertEqual(self.signet.outbox().entries()[-1]["sealed_by"], "command:/signet send")
        self.assertIn("No held email", self.signet.command(f"send {code}"))

    def test_last_names_the_email_held_most_recently(self):
        self.assertIn("No email is waiting", self.signet.command("send last"))
        self.hold_one()
        _, newer = self.call({**MAIL, "subject": "newer"}, gate_open=True)
        shown = self.signet.command("send last")
        self.assertIn("newer", shown)
        self.assertIn("Nothing was sent yet", shown)
        self.assertIn(f"/signet send {newer['code']}", shown)
        self.assertIn("Sealed", self.signet.command("send"))
        self.assertEqual(len(self.eml()), 1)
        self.assertIn("Q3 figures", self.signet.command("show last"))
        self.assertIn("Usage", self.signet.command("send nonsense"))

    def test_send_right_after_show_needs_no_second_look(self):
        code = self.hold_one()
        self.assertIn("figures attached.", self.signet.command(f"show {code}"))
        self.assertIn("Sealed", self.signet.command(f"send {code}"))
        self.assertEqual(len(self.eml()), 1)

    def test_a_planted_file_is_shown_before_anything_can_be_sent(self):
        """A file written into the outbox by something else is read to the person like any other."""
        core = module("core")
        planted = core.build_draft({"from": "ada@example.org", "to": ["eve@evil.example"], "subject": "Wire", "body": "wire the money"})
        self.signet.outbox().hold(planted, "planted")
        answer = self.signet.command(f"send {planted.code}")
        self.assertIn("eve@evil.example", answer)
        self.assertIn("wire the money", answer)
        self.assertIn("Nothing was sent yet", answer)
        self.assertEqual(self.eml(), [])

    def test_a_file_swapped_after_it_was_read_is_read_again(self):
        code = self.hold_one()
        self.signet.command(f"show {code}")
        core = module("core")
        other = core.build_draft({**MAIL, "to": ["eve@evil.example"]})
        path = self.data / "pending" / f"{code}.json"
        record = json.loads(path.read_text())
        record["draft"], record["digest"] = other.to_record(), other.digest
        path.write_text(json.dumps(record))
        self.assertIn("No held email", self.signet.command(f"send {code}"))  # the name no longer matches the content
        self.assertEqual(self.eml(), [])

    def test_send_while_the_prompt_is_still_open_does_not_send_twice(self):
        directive = self.signet.pre_tool_call(tool_name=schemas.SEND_TOOL, args=MAIL)
        self.signet.pre_approval_request(pattern_key=f"plugin_rule:{directive['rule_key']}")
        code = self.signet.build(MAIL).code
        self.signet.command(f"show {code}")
        self.assertIn("Sealed", self.signet.command(f"send {code}"))
        # The person then also answers the old prompt: it must not produce a second message.
        self.signet.post_approval_response(pattern_key=f"plugin_rule:{directive['rule_key']}", choice="once")
        self.assertEqual(json.loads(self.signet.send_mail(MAIL))["status"], "held")
        self.assertEqual(len(self.eml()), 1)

    def test_an_approval_after_the_draft_was_dropped_sends_nothing(self):
        """Also when the prompt and /signet are served by different processes: the held file is the witness."""
        directive = self.signet.pre_tool_call(tool_name=schemas.SEND_TOOL, args=MAIL)
        other_process = plugin.Signet(self.ctx, data_dir=self.data)  # shares the outbox, not the seals
        self.assertIn("Nothing was sent", other_process.command("drop last"))
        self.signet.post_approval_response(pattern_key=f"plugin_rule:{directive['rule_key']}", choice="once")
        result = json.loads(self.signet.send_mail(MAIL))
        self.assertEqual(result["status"], "already_handled")
        self.assertEqual(self.eml(), [])

    def test_two_senders_of_the_same_held_email_cannot_both_send(self):
        """The approval path and /signet send race for one file: a rename is won once."""
        outbox = self.signet.outbox()
        code = self.hold_one()
        self.assertTrue(outbox.claim(code))
        self.assertFalse(outbox.claim(code))
        self.assertEqual(self.held(), [])
        outbox.settle(code)
        # In the plugin: the approval arrives after /signet send took the email.
        directive = self.signet.pre_tool_call(tool_name=schemas.SEND_TOOL, args={**MAIL, "subject": "race"})
        self.signet.post_approval_response(pattern_key=f"plugin_rule:{directive['rule_key']}", choice="once")
        raced = self.signet.build({**MAIL, "subject": "race"}).code
        self.assertTrue(self.signet.outbox().claim(raced))  # the other process got there first
        self.assertEqual(json.loads(self.signet.send_mail({**MAIL, "subject": "race"}))["status"], "already_handled")
        self.assertEqual(self.eml(), [])

    def test_a_send_that_died_gives_the_email_back_marked(self):
        code = self.hold_one()
        outbox = self.signet.outbox()
        self.assertTrue(outbox.claim(code))
        claimed = self.data / "sending" / f"{code}.json"
        old = claimed.stat().st_mtime - 700
        __import__("os").utime(claimed, (old, old))
        (draft, record), = outbox.pending()
        self.assertEqual(record["state"], "failed")
        self.assertIn("may or may not have left", record["reason"])
        self.assertFalse(claimed.exists())

    def test_send_refuses_inside_a_scheduled_run(self):
        code = self.hold_one()
        self.ctx.cron = object()
        self.assertIn("scheduled run", self.signet.command(f"send {code}"))
        self.assertEqual(self.eml(), [])

    def test_drop(self):
        code = self.hold_one()
        self.assertIn("Nothing was sent", self.signet.command(f"drop {code}"))
        self.assertEqual(self.held(), [])
        self.assertEqual(self.eml(), [])

    def test_a_held_file_edited_on_disk_is_not_sendable(self):
        code = self.hold_one()
        path = self.data / "pending" / f"{code}.json"
        record = json.loads(path.read_text())
        record["draft"]["to"] = ["eve@evil.example"]
        path.write_text(json.dumps(record))
        self.assertIn("No held email", self.signet.command(f"send {code}"))
        self.assertEqual(self.eml(), [])

    def test_a_held_file_forged_with_a_matching_fingerprint_still_passes_the_draft_checks(self):
        """Someone who can write the outbox folder can name a file after its own digest: it gets no shortcut."""
        core = module("core")
        forged = core.Draft(sender="Eve <eve@evil.example>", to=("bob@example.com",), cc=(),
                            subject="Pay" + chr(0x200B) + "ment", body="hidden" + chr(0x202E) + " text")
        self.signet.outbox().hold(forged, "forged")
        self.ctx.settings["allowed_from"] = ["ada@example.org"]
        self.assertIn("not one the owner allowed", self.signet.command(f"send {forged.code}"))
        self.ctx.settings["allowed_from"] = []
        self.assertIn("not a draft Signet would have written", self.signet.command(f"send {forged.code}"))
        self.assertIn("not a draft Signet would have written", self.signet.command(f"send {forged.code}"))
        self.assertEqual(self.eml(), [])

    def test_an_attachment_swapped_while_held_is_not_sent(self):
        report = self.data / "report.txt"
        report.write_text("v1")
        _, result = self.call({**MAIL, "attachments": [str(report)]}, gate_open=True)
        report.write_text("v2 with other numbers")
        self.assertIn("changed after", self.signet.command(f"send {result['code']}"))
        self.assertEqual(self.eml(), [])

    def test_log_and_usage(self):
        self.call(MAIL)
        self.assertIn("sent", self.signet.command("log"))
        self.assertIn("/signet send CODE", self.signet.command("what"))
        self.assertIn("Usage", self.signet.command("send what"))

    def test_outbox_tool_is_read_only_and_has_no_bodies(self):
        self.hold_one()
        listing = self.signet.outbox_tool({})
        self.assertIn("bob@example.com", listing)
        self.assertNotIn("figures attached", listing)
        self.assertEqual(self.eml(), [])


class Transports(Harness):
    def test_command_transport_hands_over_the_exact_message(self):
        target = self.data / "handed.eml"
        script = "import sys, pathlib; pathlib.Path(sys.argv[1]).write_bytes(sys.stdin.buffer.read())"
        self.ctx.settings.update(transport="command", send_command=[sys.executable, "-c", script, str(target)])
        _, result = self.call(MAIL)
        self.assertEqual(result["status"], "sent")
        self.assertTrue(result["sent"])
        message = BytesParser(policy=policy.default).parsebytes(target.read_bytes())
        self.assertEqual(message["Subject"], "Q3 figures")

    def test_a_failing_mailer_is_reported_and_never_retried(self):
        counter = self.data / "runs"
        script = "import sys, pathlib; p = pathlib.Path(sys.argv[1]); p.write_text(p.read_text() + 'x' if p.exists() else 'x'); sys.exit(3)"
        self.ctx.settings.update(transport="command", send_command=[sys.executable, "-c", script, str(counter)])
        _, result = self.call(MAIL)
        self.assertEqual(result["status"], "failed")
        self.assertIn("Do not retry", result["message"])
        self.assertEqual(counter.read_text(), "x")
        self.assertEqual(len(self.held()), 1)
        self.assertEqual(self.events()[-1], "failed")

    def test_a_shell_line_is_not_accepted_as_a_command(self):
        self.ctx.settings.update(transport="command", send_command="msmtp -t; rm -rf /")
        _, result = self.call(MAIL)
        self.assertEqual(result["status"], "failed")
        self.assertIn("list of words", result["detail"])

    def test_smtp_transport(self):
        sink = SmtpSink()
        self.addCleanup(sink.close)
        self.ctx.settings.update(transport="smtp", smtp_host="127.0.0.1", smtp_port=sink.port, smtp_security="none", seal_header=True)
        report = self.data / "report.txt"
        report.write_text("figures")
        _, result = self.call({**MAIL, "cc": ["Carol <carol@example.com>"], "attachments": [str(report)]})
        self.assertEqual(result["status"], "sent")
        received = sink.received[0]
        self.assertEqual(received["from"], "ada@example.org")
        self.assertEqual(received["to"], ["bob@example.com", "carol@example.com"])
        message = BytesParser(policy=policy.default).parsebytes(received["data"])
        self.assertEqual(str(message["X-Signet-Seal"]).strip(), self.signet.build({**MAIL, "cc": ["Carol <carol@example.com>"], "attachments": [str(report)]}).digest)
        self.assertEqual([part.get_filename() for part in message.iter_attachments()], ["report.txt"])

    def test_plain_smtp_is_for_this_machine_only(self):
        self.ctx.settings.update(transport="smtp", smtp_host="smtp.example.com", smtp_security="none")
        _, result = self.call(MAIL)
        self.assertEqual(result["status"], "failed")
        self.assertIn("this machine only", result["detail"])

    def test_unknown_transport(self):
        self.ctx.settings["transport"] = "fax"
        _, result = self.call(MAIL)
        self.assertEqual(result["status"], "failed")


class Registration(unittest.TestCase):
    def test_register_wires_what_the_manifest_declares(self):
        ctx = FakeContext()
        load().register(ctx)
        self.assertEqual(sorted(ctx.tools), ["signet_outbox", "signet_send_mail"])
        self.assertEqual(sorted(ctx.hooks), ["post_approval_response", "pre_approval_request", "pre_tool_call"])
        self.assertEqual(list(ctx.commands), ["signet"])
        manifest = (Path(__file__).resolve().parent.parent / "plugin.yaml").read_text()
        for name in (*ctx.tools, *ctx.hooks):
            self.assertIn(f"  - {name}\n", manifest)
        self.assertIn(f"version: {load().__version__}\n", manifest)


if __name__ == "__main__":
    unittest.main()
