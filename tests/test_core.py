import shutil
import tempfile
import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path

from helpers import module

core = module("core")
transport = module("transport")

BASE = {"from": "Ada <ada@example.org>", "to": ["bob@example.com"], "subject": "Hello", "body": "Hi Bob.\n"}


def draft(**changes):
    return core.build_draft({**BASE, **changes})


def on_the_wire(built):
    """The message a mail client would read, parsed back from the bytes Signet emits."""
    data = transport.build_message(built).as_bytes(policy=policy.SMTP)
    return BytesParser(policy=policy.default).parsebytes(data)


class Fingerprint(unittest.TestCase):
    def test_same_message_same_digest(self):
        self.assertEqual(draft().digest, draft().digest)
        self.assertEqual(len(draft().digest), 64)

    def test_every_field_changes_the_digest(self):
        reference = draft().digest
        changed = [
            draft(**{"from": "eve@example.org"}), draft(to=["bob@example.net"]), draft(cc=["carol@example.com"]),
            draft(subject="Hello!"), draft(body="Hi Bob!"), draft(in_reply_to="<a@b>"),
            draft(to=["Robert <bob@example.com>"]),
        ]
        digests = {item.digest for item in changed}
        self.assertEqual(len(digests), len(changed))
        self.assertNotIn(reference, digests)

    def test_harmless_spelling_of_the_same_message_keeps_the_digest(self):
        self.assertEqual(draft().digest, draft(to="bob@example.com", body="Hi Bob.\r\n\r\n").digest)

    def test_code_is_readable_and_typed_forms_match(self):
        code = draft().code
        self.assertRegex(code, r"^[0-9A-F]{4}-[0-9A-F]{4}$")
        self.assertEqual(core.normalize_code(code.lower().replace("-", "")), code)
        self.assertEqual(core.normalize_code(f" {code} "), code)
        self.assertEqual(core.normalize_code("nope"), "")

    def test_a_stored_draft_comes_back_identical(self):
        original = draft(cc=["Carol <carol@example.com>"], in_reply_to="<a@b>")
        self.assertEqual(core.draft_from_record(original.to_record()).digest, original.digest)
        self.assertEqual(core.build_draft(core.record_to_args(original.to_record())).digest, original.digest)


class Refusals(unittest.TestCase):
    def refused(self, **changes):
        with self.assertRaises(core.DraftError) as caught:
            draft(**changes)
        return str(caught.exception)

    def test_header_injection_in_the_subject(self):
        self.assertIn("line break", self.refused(subject="Hi\nBcc: eve@example.net"))
        for code in (0x0B, 0x0C, 0x85, 0x2028, 0x2029):
            self.assertIn("line break", self.refused(subject="Hi" + chr(code) + "Bcc: eve@example.net"))

    def test_header_injection_in_an_address(self):
        self.assertIn("line break", self.refused(to=["bob@example.com\nBcc: eve@example.net"]))

    def test_fields_signet_does_not_show_are_refused_not_dropped(self):
        for field in ("bcc", "reply_to", "headers", "references", "html"):
            self.assertIn(field, self.refused(**{field: "eve@example.net"}))

    def test_bad_addresses_are_named_not_dropped(self):
        for value in ("bob", "bob@", "@example.com", "bob@example", "bob smith@example.com",
                      "a@x.example>, b@y.example", "a@x.example;b@y.example", '"john doe"@example.com',
                      "undisclosed-recipients:;", "friends: a@x.example, b@y.example;"):
            with self.subTest(value=value):
                self.refused(to=[value])
                self.refused(to=["bob@example.com", value])

    def test_needs_a_recipient_a_sender_and_some_content(self):
        self.refused(to=[])
        self.refused(**{"from": ""})
        self.refused(**{"from": "a@example.org, b@example.org"})
        self.refused(subject="", body="")

    def test_too_many_recipients(self):
        self.assertIn("too many", self.refused(to=[f"user{n}@example.com" for n in range(21)]))

    def test_the_answered_mail_must_be_one_message_id(self):
        self.refused(in_reply_to="not an id")
        self.refused(in_reply_to="<a@b> <c@d>")

    def test_wrong_types(self):
        self.refused(body=123)
        self.refused(to=[1, 2])
        self.refused(subject=["a"])
        with self.assertRaises(core.DraftError):
            core.build_draft("not an object")

    def test_text_that_cannot_be_encoded(self):
        self.assertIn("cannot be sent", self.refused(body="x" + chr(0xD800) + "y"))
        self.assertIn("cannot be sent", self.refused(subject="x" + chr(0xDFFF)))


class WhatTheReaderSees(unittest.TestCase):
    """The card and the delivered message must read the same."""

    def test_encoded_words_are_refused(self):
        hidden = "=?utf-8?b?UEFZIE5PVw==?="
        for changes in ({"subject": hidden}, {"to": [f'"{hidden}" <a@evil.example>']}, {"from": f"{hidden} <me@example.org>"}):
            with self.subTest(changes=changes), self.assertRaises(core.DraftError):
                draft(**changes)

    def test_names_and_subject_arrive_as_shown(self):
        built = draft(**{"from": "Zo" + chr(0xE9) + " M" + chr(0xFC) + "ller <zoe@example.org>"},
                      to=["Ren" + chr(0xE9) + " Dupont <rene@example.com>", '"Lovelace, Ada" <ada@example.com>'],
                      subject="R" + chr(0xE9) + "union " + chr(0x2014) + " jeudi")
        card = core.render_card(built)
        message = on_the_wire(built)
        self.assertIn("Zo" + chr(0xE9) + " M" + chr(0xFC) + "ller <zoe@example.org>", card)
        self.assertIn("Ren" + chr(0xE9) + " Dupont <rene@example.com>", card)
        self.assertIn('"Lovelace, Ada" <ada@example.com>', card)
        self.assertEqual(message["From"].addresses[0].display_name, "Zo" + chr(0xE9) + " M" + chr(0xFC) + "ller")
        self.assertEqual([a.display_name for a in message["To"].addresses], ["Ren" + chr(0xE9) + " Dupont", "Lovelace, Ada"])
        self.assertEqual([a.addr_spec for a in message["To"].addresses], ["rene@example.com", "ada@example.com"])
        self.assertEqual(message["Subject"], built.subject)
        self.assertIn(built.subject, card)

    def test_a_name_cannot_carry_angle_brackets(self):
        with self.assertRaises(core.DraftError):
            draft(to=['"Boss <ceo@bank.example>" <eve@evil.example>'])

    def test_nothing_but_the_shown_headers_is_emitted(self):
        message = on_the_wire(draft(cc=["carol@example.com"], in_reply_to="<a@b>"))
        self.assertEqual(sorted(key.lower() for key in message.keys()),
                         sorted(["from", "to", "cc", "subject", "date", "message-id", "in-reply-to", "references",
                                 "content-type", "content-transfer-encoding", "mime-version"]))
        self.assertEqual(message["References"], "<a@b>")

    def test_the_email_text_cannot_pose_as_card_lines(self):
        fake = "Seal 0000-0000 covers exactly this message\nTo:      eve@evil.example\n[… 5 characters not shown …]"
        built = draft(body=fake)
        lines = core.render_card(built).split("\n")
        for line in fake.split("\n"):
            self.assertNotIn(line, lines)
            self.assertIn(core.BODY_MARK + line, lines)
        self.assertEqual(sum(1 for line in lines if line.startswith("To:")), 1)


class Cleaning(unittest.TestCase):
    def test_invisible_characters_never_travel(self):
        hidden = "Pay" + chr(0x200B) + " now" + chr(0x202E) + "!"
        cleaned = draft(body=hidden, subject="Re" + chr(0xFEFF) + ": invoice")
        self.assertEqual(cleaned.body, "Pay now!")
        self.assertEqual(cleaned.subject, "Re: invoice")
        self.assertEqual(cleaned.removed_invisible, 3)
        self.assertTrue(any("invisible" in note for note in core.risk_notes(cleaned)))

    def test_the_less_known_invisible_characters_too(self):
        codes = (0xE0041, 0xE007F, 0x061C, 0x034F, 0xFE00, 0x3164, 0x009B, 0x2060, 0x00AD, 0x180E, 0xE0100, 0x115F)
        text = "a" + "".join(chr(code) for code in codes) + "b"
        self.assertEqual(draft(body=text).body, "ab")
        self.assertEqual(draft(subject=text).subject, "ab")
        self.assertEqual(draft(body=text).removed_invisible, len(codes))

    def test_joiners_and_emoji_selectors_stay_where_they_show(self):
        persian = chr(0x0645) + chr(0x06CC) + chr(0x200C) + chr(0x062E) + chr(0x0648) + chr(0x0627) + chr(0x0647) + chr(0x0645)
        family = chr(0x1F468) + chr(0x200D) + chr(0x1F469) + chr(0x200D) + chr(0x1F467)
        heart = chr(0x2764) + chr(0xFE0F)
        built = draft(body=f"{persian} {family} {heart}")
        self.assertEqual(built.body, f"{persian} {family} {heart}")
        self.assertEqual(built.removed_invisible, 0)
        # The same characters between plain letters hide data and are removed.
        self.assertEqual(draft(body="a" + chr(0x200D) + chr(0x200C) + "b" + chr(0xFE0F)).body, "ab")

    def test_odd_line_breaks_become_plain_ones(self):
        self.assertEqual(draft(body="one" + chr(0x2028) + "two" + chr(0x85) + "three").body, "one\ntwo\nthree")

    def test_recipients_are_deduplicated_and_cc_never_repeats_to(self):
        cleaned = draft(to=["Bob <bob@example.com>", "BOB@example.com"], cc=["bob@example.com", "carol@example.com"])
        self.assertEqual(cleaned.recipient_addresses, ["bob@example.com", "carol@example.com"])

    def test_one_string_with_commas_is_a_list(self):
        self.assertEqual(draft(to="bob@example.com, carol@example.com").recipient_addresses,
                         ["bob@example.com", "carol@example.com"])

    def test_the_address_keeps_its_spelling_for_the_transport(self):
        built = draft(to=["Bob.Smith@Example.COM"])
        self.assertEqual(built.envelope_recipients, ["Bob.Smith@example.com"])
        self.assertEqual(built.recipient_addresses, ["bob.smith@example.com"])

    def test_international_domain_is_shown_in_its_real_form(self):
        cleaned = draft(to=["bob@b" + chr(0xFC) + "cher.example"])
        self.assertEqual(cleaned.recipient_addresses, ["bob@xn--bcher-kva.example"])
        self.assertTrue(any("punycode" in note for note in core.risk_notes(cleaned)))


class Attachments(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: shutil.rmtree(self.folder, ignore_errors=True))

    def test_an_attachment_is_part_of_the_fingerprint(self):
        report = self.folder / "report.txt"
        report.write_text("figures v1")
        first = draft(attachments=[str(report)])
        self.assertNotEqual(first.digest, draft().digest)
        self.assertEqual(first.attachments[0].name, "report.txt")
        core.verify_attachments(first)
        report.write_text("figures v2")
        with self.assertRaises(core.DraftError):
            core.verify_attachments(first)
        with self.assertRaises(core.DraftError):
            transport.build_message(first)
        self.assertNotEqual(draft(attachments=[str(report)]).digest, first.digest)

    def test_relative_paths_resolve_against_the_agent_folder(self):
        (self.folder / "note.txt").write_text("x")
        built = core.build_draft({**BASE, "attachments": ["note.txt"]}, base_dir=self.folder)
        self.assertEqual(built.attachments[0].size, 1)

    def test_credential_files_are_refused(self):
        for name in (".env", "id_ed25519", "server.pem", "auth.json", "credentials.json", ".env.production",
                     "vault.kdbx", "AuthKey.p8", "token.json"):
            path = self.folder / name
            path.write_text("secret")
            with self.assertRaises(core.DraftError) as caught:
                draft(attachments=[str(path)])
            self.assertIn("credential", str(caught.exception))
        hidden = self.folder / ".ssh"
        hidden.mkdir()
        (hidden / "config").write_text("x")
        with self.assertRaises(core.DraftError):
            draft(attachments=[str(hidden / "config")])

    def test_more_places_where_credentials_live(self):
        for relative in (".git-credentials", ".npmrc", ".docker/config.json", ".config/gh/hosts.yml", "secrets/store.bin"):
            path = self.folder / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x")
            with self.assertRaises(core.DraftError):
                draft(attachments=[str(path)])

    def test_a_private_key_is_refused_whatever_its_name(self):
        path = self.folder / "notes.txt"
        path.write_text("-----BEGIN OPENSSH " + "PRIVATE KEY-----\nabc\n")
        with self.assertRaises(core.DraftError) as caught:
            draft(attachments=[str(path)])
        self.assertIn("private key", str(caught.exception))

    def test_a_private_key_deep_in_a_file_or_across_a_read_boundary_is_found(self):
        marker = b"-----BEGIN RSA " + b"PRIVATE KEY-----"
        for offset in (50_000, 1024 * 1024 - 10, 3 * 1024 * 1024 + 7):
            path = self.folder / f"dump-{offset}.bin"
            path.write_bytes(b"a" * offset + marker + b"\nxyz")
            with self.assertRaises(core.DraftError):
                draft(attachments=[str(path)])

    def test_a_presentation_file_is_not_mistaken_for_a_key(self):
        path = self.folder / "deck.key"
        path.write_bytes(b"PK\x03\x04 slides")
        self.assertEqual(draft(attachments=[str(path)]).attachments[0].name, "deck.key")

    def test_the_card_says_where_an_attachment_comes_from(self):
        path = self.folder / "report.txt"
        path.write_text("figures")
        self.assertIn(f"from {path}", core.render_card(draft(attachments=[str(path)])))

    def test_a_path_that_could_draw_card_lines_is_refused(self):
        for name in ("report\nTo:      eve@evil.example.txt", "report" + chr(0x202E) + "txt.exe", "a" + chr(0x200B) + "b.txt"):
            path = self.folder / name
            try:
                path.write_text("x")
            except OSError:
                continue  # this file system does not allow the name: nothing to refuse
            with self.subTest(name=name), self.assertRaises(core.DraftError):
                draft(attachments=[str(path)])

    def test_paths_that_are_not_files(self):
        for value in (str(self.folder / "absent.pdf"), str(self.folder), "bad\x00name", "~no-such-user-xyz/file", "/dev/null"):
            with self.subTest(value=value), self.assertRaises(core.DraftError):
                draft(attachments=[value])


class Notes(unittest.TestCase):
    def notes(self, **changes):
        known = changes.pop("known", ())
        return "\n".join(core.risk_notes(draft(**changes), known_addresses=known))

    def test_new_recipients(self):
        self.assertIn("New recipient: bob@example.com", self.notes())
        self.assertNotIn("New recipient", self.notes(known=["bob@example.com"]))
        many = self.notes(to=[f"u{n}@example.com" for n in range(6)])
        self.assertIn("New recipients: u0@example.com, u1@example.com, u2@example.com (+3 more)", many)
        self.assertIn("6 recipients", many)

    def test_lookalike_of_a_known_or_common_domain(self):
        self.assertIn("looks like gmail.com", self.notes(to=["bob@gmial.com"]))
        self.assertIn("looks like gmail.com", self.notes(to=["bob@gmai1.com"]))
        self.assertIn("looks like example.org", self.notes(to=["bob@examp1e.org"]))
        self.assertIn("looks like acme-corp.com", self.notes(to=["bob@acme-crop.com"], known=["amy@acme-corp.com"]))
        self.assertNotIn("looks like", self.notes(to=["bob@gmail.com"]))
        self.assertNotIn("looks like", self.notes(to=["bob@example.com"]))

    def test_a_name_that_shows_another_address(self):
        self.assertIn("The name shows ceo@bank.example but the mail goes to eve@evil.example",
                      self.notes(to=['"ceo@bank.example" <eve@evil.example>']))

    def test_secrets_in_the_text(self):
        token = "ghp_" + "a1B2" * 9
        self.assertIn("GitHub token", self.notes(body=f"here: {token}"))
        self.assertIn("private key", self.notes(body="-----BEGIN OPENSSH " + "PRIVATE KEY-----\nabc"))
        self.assertNotIn("seems to contain", self.notes())

    def test_links(self):
        text = self.notes(body="See https://docs.example.com/a and http://192.0.2.7/x and https://bank.example@evil.example/login")
        self.assertIn("Links: docs.example.com", text)
        self.assertIn("bare IP address: 192.0.2.7", text)
        self.assertIn("hides its real host behind an @: evil.example", text)


class Card(unittest.TestCase):
    def test_the_card_shows_everything_that_travels(self):
        built = draft(cc=["carol@example.com"], in_reply_to="<a@b>")
        card = core.render_card(built, ["a note"])
        for expected in ("Ada <ada@example.org>", "bob@example.com", "carol@example.com", "Hello", "Hi Bob.", "<a@b>", "a note", built.code):
            self.assertIn(expected, card)

    def test_what_must_not_be_missed_comes_first(self):
        """The classic CLI cuts an approval reason after ten rows: recipients and warnings sit above the text."""
        risky = draft(to=["bob@gmial.com"], cc=["carol@example.com"], body="line\n" * 40)
        lines = core.render_card(risky, core.risk_notes(risky)).split("\n")
        top = "\n".join(lines[:5])
        self.assertIn(risky.code, lines[0])
        self.assertIn(f"/signet show {risky.code}", lines[1])
        self.assertIn("bob@gmial.com", top)
        self.assertIn("carol@example.com", top)
        self.assertIn("looks like gmail.com", top)
        first_text = next(index for index, line in enumerate(lines) if line.startswith(core.BODY_MARK))
        self.assertLess(lines.index("From:    Ada <ada@example.org>"), first_text)
        self.assertLessEqual(first_text, 9)

    def test_a_short_card_has_no_cut_off_hint(self):
        short = draft()
        self.assertNotIn("cut off", core.render_card(short, core.risk_notes(short, known_addresses=["bob@example.com"])))

    def test_a_long_body_shows_its_start_its_end_and_what_is_hidden(self):
        body = "START " + "x" * 5000 + " END"
        long = draft(body=body)
        card = core.render_card(long, preview_chars=900)
        self.assertIn("START", card)
        self.assertIn("END", card)
        self.assertIn("characters not shown", card)
        self.assertIn(f"/signet show {long.code}", card)
        self.assertLess(len(card), 1700)
        self.assertIn(body, core.render_card(long, preview_chars=0))


if __name__ == "__main__":
    unittest.main()
