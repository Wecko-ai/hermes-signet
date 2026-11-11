import time
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
    "echo hi | mail bob@example.com",
    "mail bob@example.com -s subj < body",
    "mutt -s 'Subject' bob@example.com < body.txt",
    "mutt bob@example.com < body",
    "swaks --to bob@example.com --server smtp.example.com",
    "curl --url smtps://smtp.example.com:465 --mail-from a@example.org --upload-file mail.txt",
    "ls && cat x | msmtp -t",
    'sh -c "sendmail -t < m"',
    "bash -lc 'msmtp -t < m'",
    "timeout 30 msmtp -t < m",
    "nice -n 5 msmtp -t < m",
    "sudo -u mail msmtp -t < m",
    "ssh mailhost sendmail -t < m",
    "ssh -p 2222 user@mailhost 'cat m | msmtp -t'",
    "docker exec mta sendmail -t < m",
    "if true; then msmtp -t < m; fi",
    "{ msmtp -t < m; }",
    "xargs -a list msmtp",
    'echo "$(msmtp -t < m)"',
    "env MAILRC=/dev/null mail -s hi bob@example.com < body",
    "nohup sendmail -t < m &",
    "aws ses send-email --from a@example.org --to b@example.com --subject hi --text body",
    "aws sesv2 send-email --cli-input-json file://mail.json",
    "python3 -c \"import smtplib; smtplib.SMTP('localhost').sendmail('a','b','c')\"",
    "python3 - <<'EOF'\nimport smtplib\nwith smtplib.SMTP('localhost') as s:\n    s.send_message(m)\nEOF",
    "uv run python -c \"import smtplib; smtplib.SMTP_SSL('h').login('u','p')\"",
    "node -e \"require('nodemailer').createTransport({}).sendMail({})\"",
    "bash <<'EOF'\ncat mail.eml | msmtp -t\nEOF",
    "curl -X POST https://api.resend.com/emails -d @mail.json",
    "curl https://api.resend.com/emails --json '{\"to\": \"bob@example.com\"}'",
    "curl https://api.sendgrid.com/v3/mail/send -d '{}'",
    "curl -s https://gmail.googleapis.com/gmail/v1/users/me/messages/send -d @raw.json",
    "gws gmail users messages send --params '{}'",
    "python3 google_api.py gmail send --to bob@example.com",
    "osascript -e 'tell application \"Mail\" to send theMessage'",
    "hima\"laya\" message send < mail.eml",
    "m's'mtp -t < m",
    "send\\mail -t < m",
    "echo 'cat m | msmtp -t' | sh",
    "printf 'msmtp -t < m\\n' | bash -s",
    "echo \"import smtplib; smtplib.SMTP('h').sendmail(a, b, c)\" | python3",
    "cat <<'EOF' | python3 -\nimport smtplib\nsmtplib.SMTP('h').send_message(m)\nEOF",
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
    "msmtp --serverinfo --host=smtp.example.com",
    "sendmail -bp",
    "mailq; exim -bp",
    "exim4 -bpc",
    "brew install msmtp",
    "cat docs/mail-setup.md",
    "echo 'use mail -s to send' > notes.txt",
    'echo "restart postfix; sendmail queue is empty"',
    'git commit -m "docs: update; msmtp setup notes"',
    "git log --grep='send email'",
    "cat > README.md <<'EOF'\nTo send by hand:\nmsmtp -t < mail.eml\nsendmail -t < mail.eml\nEOF",
    "grep -rn smtplib .",
    "pip list | grep -i python; grep -rn smtplib .",
    "python3 -c \"import smtplib; print(smtplib.__file__)\"",
    "sed -i 's/smtplib/smtp/' x.py && python3 x.py",
    "npm ls nodemailer && node -v",
    "grep -rn Send-MailMessage ~/scripts",
    "osascript -e 'tell application \"Mail\" to get unread count' | grep -v send",
    "curl https://api.resend.com/domains",
    "curl -s https://api.resend.com/emails",
    "curl -s https://api.resend.com/emails/abc123",
    "curl https://example.com/emails",
    "python3 scripts/report.py --no-mail",
    "gws gmail users messages list",
    "gws gmail users messages list --params '{\"q\":\"subject:send\"}'",
    "mail -f archive.mbox",
    "mutt -f inbox",
    "mailq",
    "aws ses list-identities",
    "# msmtp -t < mail.eml",
    "echo done # then run: sendmail -t",
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
        sends = [
            "import smtplib\ns = smtplib.SMTP('x')\ns.sendmail(a, b, c)",
            "import requests\nrequests.post('https://api.resend.com/emails', json=m)",
            "import resend\nresend.Emails.send(params)",
            "import boto3\nboto3.client('ses').send_email(Source=a, Destination=d, Message=m)",
            "from django.core.mail import send_mail\nsend_mail('s', 'b', 'a@example.org', ['b@example.com'])",
            "import subprocess\nsubprocess.run(['msmtp', '-t'], input=data)",
            "import os\nos.system('himalaya message send < m.eml')",
        ]
        for code in sends:
            with self.subTest(code=code):
                self.assertTrue(guard.detect("execute_code", {"code": code}))
        harmless = [
            "print('hello')",
            "import ast\nBANNED = {'smtplib', 'socket'}\nprint(BANNED)",
            "notes = 'we use sendmail on the server'\nprint(notes)",
            "import requests\nprint(requests.get('https://api.resend.com/emails').json())",
            "import boto3\nprint(boto3.client('s3').list_buckets())",
        ]
        for code in harmless:
            with self.subTest(code=code):
                self.assertIsNone(guard.detect("execute_code", {"code": code}))

    def test_text_typed_into_a_running_program(self):
        self.assertTrue(guard.detect("process_manage", {"action": "submit", "session_id": "proc_1", "data": "msmtp -t < mail.eml"}))
        self.assertTrue(guard.detect("process_manage", {"action": "write", "data": "import smtplib\nsmtplib.SMTP('h').sendmail(a, b, c)\n"}))
        self.assertIsNone(guard.detect("process_manage", {"action": "submit", "data": "ls -la"}))
        self.assertIsNone(guard.detect("process_manage", {"action": "poll", "session_id": "proc_1"}))

    def test_what_is_too_large_to_read_is_not_waved_through(self):
        padding = "echo padding\n" * 40_000
        self.assertGreater(len(padding), 400_000)
        self.assertEqual(guard.detect("terminal", {"command": padding + "msmtp -t < m"}), guard.TOO_LARGE)
        self.assertIsNone(guard.detect("terminal", {"command": padding + "ls -la"}))
        self.assertTrue(guard.detect("terminal", {"command": "msmtp -t < m\n" + padding}))

    def test_other_tools_and_odd_arguments_are_ignored(self):
        self.assertIsNone(guard.detect("write_file", {"content": "msmtp -t", "path": "notes.md"}))
        self.assertIsNone(guard.detect("terminal", None))
        self.assertIsNone(guard.detect("terminal", {"command": 42}))
        self.assertIsNone(guard.detect("terminal", {}))
        self.assertIsNone(guard.detect("terminal", {"command": "echo 'unclosed quote; ls"}))
        self.assertTrue(guard.detect("terminal", {"command": "echo 'unclosed quote; msmtp -t"}))

    def test_large_and_hostile_input_is_read_in_linear_time(self):
        hostile = [
            "\n" * 100_000,
            "mail\n" * 50_000,
            "gws gmail " * 20_000,
            "osascript Mail " * 20_000,
            "agentmail " * 20_000,
            "curl " * 40_000 + "smtp",
            "echo " + "$(" * 30_000 + "mail",
            "sh -c " * 30_000 + "mail",
            "msmtp" + " <<EOF" * 30_000,
            "'" + "mail " * 60_000,
            "a=1 " * 60_000 + "mail",
            "sudo " * 60_000 + "mail",
        ]
        for text in hostile:
            started = time.perf_counter()
            guard.detect("terminal", {"command": text})
            guard.detect("execute_code", {"code": text})
            self.assertLess(time.perf_counter() - started, 2.0, text[:20])


if __name__ == "__main__":
    unittest.main()
