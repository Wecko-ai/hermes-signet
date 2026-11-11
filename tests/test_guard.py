import unittest

from helpers import module

guard = module("guard")

SENDS = [
    "himalaya message send < mail.eml",
    "cat mail.eml | himalaya message send --no-save",
    "/opt/homebrew/bin/himalaya -a work template send < draft.txt",
    "himalaya message reply 42",
    "himalaya send",
    "FOO=1 himalaya message forward 7",
    "printf 'Subject: hi\\n\\nbody' | msmtp -t",
    "cat mail.eml | /usr/sbin/sendmail -t",
    "sudo sendmail bob@example.com < mail.txt",
    "echo body | mail -s 'Subject' bob@example.com",
    "echo body | mailx -a file.txt -s Subject bob@example.com",
    "mutt -s 'Subject' bob@example.com < body.txt",
    "swaks --to bob@example.com --server smtp.example.com",
    "curl --url smtps://smtp.example.com:465 --mail-from a@example.org --upload-file mail.txt",
    "ls && cat x | msmtp -t",
    "python3 -c \"import smtplib; smtplib.SMTP('localhost').sendmail('a','b','c')\"",
    "python3 - <<'EOF'\nimport smtplib\nEOF",
    "node -e \"require('nodemailer').createTransport({}).sendMail({})\"",
    "curl -X POST https://api.resend.com/emails -d @mail.json",
    "curl https://api.sendgrid.com/v3/mail/send -d '{}'",
    "curl -s https://gmail.googleapis.com/gmail/v1/users/me/messages/send -d @raw.json",
    "gws gmail users messages send --params '{}'",
    "python3 google_api.py gmail send --to bob@example.com",
    "osascript -e 'tell application \"Mail\" to send theMessage'",
]

HARMLESS = [
    "ls -la",
    "himalaya envelope list",
    "himalaya message read 42",
    "himalaya message save < draft.eml",
    "himalaya message move 42 archive",
    "himalaya template reply 42",
    "himalaya --help",
    "which msmtp",
    "man sendmail",
    "grep -rn sendmail /etc/postfix",
    "msmtp --version",
    "brew install msmtp",
    "cat docs/mail-setup.md",
    "echo 'use mail -s to send' > notes.txt",
    "git log --grep='send email'",
    "grep -rn smtplib .",
    "curl https://api.resend.com/domains",
    "curl https://example.com/emails",
    "python3 scripts/report.py --no-mail",
    "gws gmail users messages list",
    "mailq",
]


class Guard(unittest.TestCase):
    def test_known_mailers_are_recognised(self):
        for command in SENDS:
            with self.subTest(command=command):
                self.assertTrue(guard.detect("terminal", {"command": command}))

    def test_ordinary_commands_are_left_alone(self):
        for command in HARMLESS:
            with self.subTest(command=command):
                self.assertIsNone(guard.detect("terminal", {"command": command}))

    def test_scripts_run_by_execute_code(self):
        self.assertEqual(guard.detect("execute_code", {"code": "import smtplib\nsmtplib.SMTP('x')"}), "SMTP script")
        self.assertTrue(guard.detect("execute_code", {"code": "requests.post('https://api.resend.com/emails', json=m)"}))
        self.assertIsNone(guard.detect("execute_code", {"code": "print('hello')"}))

    def test_other_tools_and_odd_arguments_are_ignored(self):
        self.assertIsNone(guard.detect("write_file", {"content": "msmtp -t", "path": "notes.md"}))
        self.assertIsNone(guard.detect("terminal", None))
        self.assertIsNone(guard.detect("terminal", {"command": 42}))
        self.assertIsNone(guard.detect("terminal", {}))


if __name__ == "__main__":
    unittest.main()
