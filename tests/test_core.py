import tempfile
import unittest
from pathlib import Path

from helpers import module

core = module("core")

BASE = {"from": "Ada <ada@example.org>", "to": ["bob@example.com"], "subject": "Hello", "body": "Hi Bob.\n"}


def draft(**changes):
    return core.build_draft({**BASE, **changes})


class Fingerprint(unittest.TestCase):
    def test_same_message_same_digest(self):
        self.assertEqual(draft().digest, draft().digest)
        self.assertEqual(len(draft().digest), 64)

    def test_every_field_changes_the_digest(self):
        reference = draft().digest
        changed = [
            draft(**{"from": "eve@example.org"}), draft(to=["bob@example.net"]), draft(cc=["carol@example.com"]),
            draft(subject="Hello!"), draft(body="Hi Bob!"), draft(in_reply_to="<a@b>"), draft(references="<a@b> <c@d>"),
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
        original = draft(cc=["carol@example.com"], in_reply_to="<a@b>")
        self.assertEqual(core.draft_from_record(original.to_record()).digest, original.digest)


class Refusals(unittest.TestCase):
    def refused(self, **changes):
        with self.assertRaises(core.DraftError) as caught:
            draft(**changes)
        return str(caught.exception)

    def test_header_injection_in_the_subject(self):
        self.assertIn("line break", self.refused(subject="Hi\nBcc: eve@example.net"))

    def test_header_injection_in_an_address(self):
        self.assertIn("line break", self.refused(to=["bob@example.com\nBcc: eve@example.net"]))

    def test_fields_signet_does_not_show_are_refused_not_dropped(self):
        for field in ("bcc", "reply_to", "headers"):
            self.assertIn(field, self.refused(**{field: "eve@example.net"}))

    def test_bad_addresses(self):
        for value in ("bob", "bob@", "@example.com", "bob@example", "bob smith@example.com"):
            self.refused(to=[value])

    def test_needs_a_recipient_a_sender_and_some_content(self):
        self.refused(to=[])
        self.refused(**{"from": ""})
        self.refused(**{"from": "a@example.org, b@example.org"})
        self.refused(subject="", body="")

    def test_too_many_recipients(self):
        self.assertIn("too many", self.refused(to=[f"user{n}@example.com" for n in range(21)]))

    def test_message_ids_must_look_like_message_ids(self):
        self.refused(in_reply_to="not an id")
        self.refused(in_reply_to="<a@b> <c@d>")

    def test_wrong_types(self):
        self.refused(body=123)
        self.refused(to=[1, 2])


class Cleaning(unittest.TestCase):
    def test_invisible_characters_never_travel(self):
        hidden = "Pay" + chr(0x200B) + " now" + chr(0x202E) + "!"
        cleaned = draft(body=hidden, subject="Re" + chr(0xFEFF) + ": invoice")
        self.assertEqual(cleaned.body, "Pay now!")
        self.assertEqual(cleaned.subject, "Re: invoice")
        self.assertEqual(cleaned.removed_invisible, 3)
        self.assertTrue(any("invisible" in note for note in core.risk_notes(cleaned)))

    def test_recipients_are_deduplicated_and_cc_never_repeats_to(self):
        cleaned = draft(to=["Bob <bob@example.com>", "BOB@example.com"], cc=["bob@example.com", "carol@example.com"])
        self.assertEqual(cleaned.recipient_addresses, ["bob@example.com", "carol@example.com"])

    def test_one_string_with_commas_is_a_list(self):
        self.assertEqual(draft(to="bob@example.com, carol@example.com").recipient_addresses,
                         ["bob@example.com", "carol@example.com"])

    def test_international_domain_is_shown_in_its_real_form(self):
        cleaned = draft(to=["bob@b" + chr(0xFC) + "cher.example"])
        self.assertEqual(cleaned.recipient_addresses, ["bob@xn--bcher-kva.example"])
        self.assertTrue(any("punycode" in note for note in core.risk_notes(cleaned)))


class Attachments(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.folder, ignore_errors=True))

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
        self.assertNotEqual(draft(attachments=[str(report)]).digest, first.digest)

    def test_relative_paths_resolve_against_the_agent_folder(self):
        (self.folder / "note.txt").write_text("x")
        built = core.build_draft({**BASE, "attachments": ["note.txt"]}, base_dir=self.folder)
        self.assertEqual(built.attachments[0].size, 1)

    def test_credential_files_are_refused(self):
        for name in (".env", "id_ed25519", "server.pem", "auth.json", "credentials.json", ".env.production", "vault.kdbx"):
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

    def test_a_private_key_is_refused_whatever_its_name(self):
        path = self.folder / "notes.txt"
        path.write_text("-----BEGIN OPENSSH " + "PRIVATE KEY-----\nabc\n")
        with self.assertRaises(core.DraftError) as caught:
            draft(attachments=[str(path)])
        self.assertIn("private key", str(caught.exception))

    def test_a_presentation_file_is_not_mistaken_for_a_key(self):
        path = self.folder / "deck.key"
        path.write_bytes(b"PK\x03\x04 slides")
        self.assertEqual(draft(attachments=[str(path)]).attachments[0].name, "deck.key")

    def test_missing_file(self):
        with self.assertRaises(core.DraftError):
            draft(attachments=[str(self.folder / "absent.pdf")])


class Notes(unittest.TestCase):
    def notes(self, **changes):
        known = changes.pop("known", ())
        return "\n".join(core.risk_notes(draft(**changes), known_addresses=known))

    def test_first_email_to_an_address(self):
        self.assertIn("First email to bob@example.com", self.notes())
        self.assertNotIn("First email", self.notes(known=["bob@example.com"]))

    def test_lookalike_of_a_known_or_common_domain(self):
        self.assertIn("looks like gmail.com", self.notes(to=["bob@gmial.com"]))
        self.assertIn("looks like gmail.com", self.notes(to=["bob@gmai1.com"]))
        self.assertIn("looks like example.org", self.notes(to=["bob@examp1e.org"]))
        self.assertIn("looks like acme-corp.com", self.notes(to=["bob@acme-crop.com"], known=["amy@acme-corp.com"]))
        self.assertNotIn("looks like", self.notes(to=["bob@gmail.com"]))
        self.assertNotIn("looks like", self.notes(to=["bob@example.com"]))

    def test_display_name_that_shows_another_address(self):
        self.assertIn("display name shows", self.notes(to=['"ceo@bank.example" <eve@evil.example>']))

    def test_secrets_in_the_text(self):
        token = "ghp_" + "a1B2" * 9
        self.assertIn("GitHub token", self.notes(body=f"here: {token}"))
        self.assertIn("private key", self.notes(body="-----BEGIN OPENSSH PRIVATE KEY-----\nabc"))
        self.assertNotIn("seems to contain", self.notes())

    def test_links(self):
        text = self.notes(body="See https://docs.example.com/a and http://192.0.2.7/x and https://bank.example@evil.example/login")
        self.assertIn("Links to: docs.example.com", text)
        self.assertIn("bare IP address", text)
        self.assertIn("hides its real host", text)

    def test_many_recipients(self):
        self.assertIn("6 recipients", self.notes(to=[f"u{n}@example.com" for n in range(6)]))


class Card(unittest.TestCase):
    def test_the_card_shows_everything_that_travels(self):
        card = core.render_card(draft(cc=["carol@example.com"], in_reply_to="<a@b>"), ["a note"])
        for expected in ("Ada <ada@example.org>", "bob@example.com", "carol@example.com", "Hello", "Hi Bob.", "<a@b>", "a note", draft(cc=["carol@example.com"], in_reply_to="<a@b>").code):
            self.assertIn(expected, card)

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
