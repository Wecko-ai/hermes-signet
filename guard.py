"""Recognise a tool call that would send email around Signet.

Pure module. It reads the command or script an agent is about to run and names the mailer it
found, or returns ``None``. It is a guard for well-known mailers, not a sandbox: see the README.

A shell command is read the way a shell reads it: split into simple commands with quotes
respected, then judged by the program each one runs. A mailer's name inside a quoted string, a
commit message or a file being written is text, not a send. Scripts are judged by what they
import and call. Every step is linear in the size of the input.
"""
from __future__ import annotations

import re
import shlex
from typing import Any, Optional

COMMAND_TOOLS = frozenset({"terminal", "execute_code"})
_TEXT_KEYS = ("command", "code", "script", "input")
_MAX_SCAN = 400_000   # characters read from one argument; what lies beyond is not scanned
_MAX_DEPTH = 4        # sh -c "ssh host 'sh -c …'"

# Nothing below runs unless one of these appears somewhere in the text.
_HINTS = (
    "himalaya", "msmtp", "sendmail", "ssmtp", "esmtp", "exim", "swaks", "mail", "mutt", "smtp",
    "nodemailer", "resend", "sendgrid", "mailgun", "postmark", "brevo", "mandrill", "mailersend",
    "mailtrap", "send-email", "send_email", "sendemail", "osascript", "lettre",
)

_PUNCTUATION = frozenset("();<>|&")
_SEPARATING = frozenset(";|&()")
_ASSIGNMENT = re.compile(r"^[A-Za-z_]\w*=")
_HEREDOC = re.compile(r"(?<!<)<<(?!<)-?\s*(?:'(\w+)'|\"(\w+)\"|\\?(\w+))")
_SUBSHELL = re.compile(r"\$\(([^()]{1,2000})\)|`([^`]{1,2000})`")
_SHELL_WORDS = frozenset({"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "for", "!", "{", "}", "time"})

# Programs that only start another program. Value: their options that take an argument.
_WRAPPERS: dict[str, frozenset[str]] = {
    "sudo": frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "--user", "--group", "--host", "--chdir"}),
    "doas": frozenset({"-u", "-C"}),
    "env": frozenset({"-u", "--unset", "-C", "--chdir"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "ionice": frozenset({"-c", "-n", "-p"}),
    "timeout": frozenset({"-s", "--signal", "-k", "--kill-after"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
    "xargs": frozenset({"-a", "--arg-file", "-I", "-n", "-P", "-d", "-L", "-s", "-E", "--max-args", "--max-procs", "--delimiter", "--replace"}),
    "watch": frozenset({"-n", "--interval"}),
    "exec": frozenset({"-a"}),
    "caffeinate": frozenset({"-t", "-w"}),
    "nohup": frozenset(), "command": frozenset(), "builtin": frozenset(), "setsid": frozenset(),
    "unbuffer": frozenset(), "chronic": frozenset(), "npx": frozenset(),
}
_RUNNERS = {("uv", "run"), ("poetry", "run"), ("pdm", "run"), ("pipenv", "run"), ("bundle", "exec"),
            ("npm", "exec"), ("pnpm", "exec"), ("pipx", "run")}
_RUNNER_OPTIONS = frozenset({"--with", "--python", "-p", "--project", "--directory", "--env-file", "--group", "--extra"})

_SENDMAILS = frozenset({"sendmail", "msmtp", "ssmtp", "esmtp", "exim", "exim4"})
_SENDMAIL_QUERY = re.compile(r"^(?:--version|--help|-V|--serverinfo|-S|--pretend|-P|--configure|-b[pPvVtidDh]\w*|-q\w*|-M\w*)$")
_MAILS = frozenset({"mail", "mailx", "s-nail", "bsd-mailx", "heirloom-mailx"})
_MAIL_VALUE_OPTIONS = frozenset({"-s", "-b", "-c", "-r", "-a", "-S", "-A", "-q", "-h", "-T"})
_MUTTS = frozenset({"mutt", "neomutt"})
_MUTT_VALUE_OPTIONS = frozenset({"-s", "-a", "-b", "-c", "-e", "-F", "-H", "-i", "-m"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish"})
_INTERPRETER = re.compile(r"^(?:python[\d.]*|pypy3?|node|nodejs|deno|bun|tsx|ts-node|ruby|perl|php)$")
_CONTAINERS = frozenset({"docker", "podman", "nerdctl", "kubectl"})
_SSH_VALUE_OPTIONS = frozenset({"-i", "-p", "-l", "-o", "-F", "-J", "-L", "-R", "-D", "-b", "-c", "-e", "-m", "-S", "-W", "-w", "-E", "-B", "-Q"})
_HIMALAYA_VALUE_OPTIONS = frozenset({"-a", "--account", "-c", "--config", "-f", "--folder", "-o", "--output", "--log-level"})
_GMAIL_CLIS = frozenset({"gws", "gog", "gam", "gmail", "gmailctl"})
_SEND_VERBS = frozenset({"send", "reply", "forward"})

# Hosted mail APIs. The first group is endpoints that only ever send; the second needs a body or POST.
_API_SEND_ONLY = re.compile(
    r"api\.sendgrid\.com/v3/mail/send|mandrillapp\.com/api/[\d.]+/messages/send|send\.api\.mailtrap\.io/api/send"
    r"|gmail\.googleapis\.com/[\w./-]{0,200}/messages/send|graph\.microsoft\.com/[\w./@-]{0,200}/sendMail"
    r"|api\.agentmail\.to/[\w./@-]{0,200}/messages/send",
    re.IGNORECASE,
)
_API_SEND_WITH_BODY = re.compile(
    r"api\.resend\.com/emails|api\.(?:eu\.)?mailgun\.net/v3/[\w.-]{1,200}/messages|api\.postmarkapp\.com/email"
    r"|api\.brevo\.com/v3/smtp/email|api\.mailersend\.com/v1/email|email\.[a-z0-9-]{1,40}\.amazonaws\.com",
    re.IGNORECASE,
)
_HTTP_BODY_OPTIONS = ("--data", "--form", "--json", "--upload-file", "--post-data", "--post-file", "--body-data", "--body-file")
_POSTING_CODE = re.compile(r"\bpost\b|\bPOST\b|\bfetch\s*\(|\burlopen\s*\(|\bRequest\s*\(")

# Scripts: a library has to be named and its sending call used. A bare mention is not a send.
_CODE_RULES: tuple[tuple[str, re.Pattern[str], Optional[re.Pattern[str]]], ...] = (
    ("SMTP script", re.compile(r"\b(?:smtplib|aiosmtplib)\b"), re.compile(r"\bSMTP(?:_SSL)?\s*\(|\.sendmail\s*\(|\.send_message\s*\(|\bsend\s*\(")),
    ("SMTP script", re.compile(r"\b(?:yagmail|redmail)\b"), re.compile(r"\.send\s*\(|\bSMTP\s*\(")),
    ("SMTP script", re.compile(r"\bnodemailer\b"), re.compile(r"\bcreateTransport\s*\(|\.sendMail\s*\(")),
    ("SMTP script", re.compile(r"\bNet::SMTP\b|\bEmail::Sender\b|\bPHPMailer\b|\bActionMailer\b|\bsmtp\.SendMail\b|\blettre::"), None),
    ("mail SDK", re.compile(r"\bresend\b"), re.compile(r"\b[Ee]mails\.send\s*\(")),
    ("mail SDK", re.compile(r"\bsendgrid\b|\bSendGridAPIClient\b"), re.compile(r"\.send\s*\(|\.post\s*\(")),
    ("mail SDK", re.compile(r"\bboto3\b|\baws-sdk\b|\bclient-ses\b"), re.compile(r"\bsend_(?:raw_|templated_|bulk_)?email\s*\(|\bSend(?:Raw)?EmailCommand\b|\bsendEmail\s*\(")),
    ("mail SDK", re.compile(r"\bdjango\.core\.mail\b"), re.compile(r"\bsend_mail\s*\(|\bsend_mass_mail\s*\(|\.send\s*\(")),
    ("mail SDK", re.compile(r"\b(?:mailgun|postmarker|postmark|mailersend|brevo|sib_api_v3_sdk)\b"), re.compile(r"\.send\w*\s*\(|\.create\s*\(|\.post\s*\(")),
)
_SPAWNS = re.compile(r"\bsubprocess\b|\bos\.system\b|\bos\.popen\b|\bchild_process\b|\bexecSync\b|\bspawn(?:Sync)?\s*\(|\bPopen\s*\(|\bsystem\s*\(")
_MAILER_IN_CODE = re.compile(r"\b(?:msmtp|sendmail|ssmtp|swaks|mailx)\b|\bhimalaya\b[^\n]{0,200}\bsend\b")


def detect(tool_name: str, args: Any) -> Optional[str]:
    """Name of the mailer this call would use, or ``None`` when it sends no mail that Signet knows."""
    if tool_name not in COMMAND_TOOLS or not isinstance(args, dict):
        return None
    for key in _TEXT_KEYS:
        text = args.get(key)
        if not isinstance(text, str) or not text:
            continue
        text = text[:_MAX_SCAN]
        lowered = text.lower()
        if not any(hint in lowered for hint in _HINTS):
            continue
        label = _scan_code(text) if tool_name == "execute_code" else _scan_shell(text, 0)
        if label:
            return label
    return None


# --- shell ------------------------------------------------------------------------------------------

def _scan_shell(text: str, depth: int) -> Optional[str]:
    if depth > _MAX_DEPTH:
        return None
    lines = text.replace("\\\n", " ").split("\n")
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        body = None
        heredoc = _HEREDOC.search(line)
        if heredoc:
            word = heredoc.group(1) or heredoc.group(2) or heredoc.group(3)
            start = index
            while index < len(lines) and lines[index].strip() != word:
                index += 1
            body = "\n".join(lines[start:index])
            index += 1
            line = line[:heredoc.start()] + " " + line[heredoc.end():]
        if not line.strip():
            continue
        for command in _simple_commands(line):
            label = _judge(command, body, depth)
            if label:
                return label
    return None


def _words(line: str) -> list[str]:
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:  # an unclosed quote: fall back to a plain split, operators set apart
        return "".join(f" {char} " if char in _PUNCTUATION else char for char in line).split()


def _simple_commands(line: str) -> list[list[str]]:
    """The simple commands of one line: what stands between ``;``, ``|``, ``&&``, parentheses."""
    commands: list[list[str]] = []
    current: list[str] = []
    skip_target = False
    for word in _words(line):
        if skip_target:
            skip_target = False
            continue
        if word and all(char in _PUNCTUATION for char in word):
            if any(char in _SEPARATING for char in word):
                if current:
                    commands.append(current)
                    current = []
            else:
                skip_target = True  # < file, > file, >> file
            continue
        if not current and word.startswith("#"):
            break  # the rest of the line is a comment
        current.append(word)
    if current:
        commands.append(current)
    return commands


def _program(word: str) -> str:
    return word.strip("`'\"\\").rsplit("/", 1)[-1].lower()


def _positionals(args: list[str], value_options: frozenset[str] = frozenset()) -> list[str]:
    """Arguments that are not options, nor the value of an option known to take one."""
    result: list[str] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
        elif arg.startswith("-") and len(arg) > 1:
            skip = arg in value_options
        else:
            result.append(arg)
    return result


def _unwrap(words: list[str]) -> list[str]:
    """Drop shell keywords, variable assignments and wrapper programs in front of the real command."""
    for _ in range(12):
        if not words:
            return words
        head = _program(words[0])
        if words[0] in _SHELL_WORDS or _ASSIGNMENT.match(words[0]):
            words = words[1:]
        elif len(words) > 1 and (head, words[1]) in _RUNNERS:
            words = _after_options(words[2:], _RUNNER_OPTIONS)
        elif head in _WRAPPERS:
            rest = _after_options(words[1:], _WRAPPERS[head])
            if head == "timeout" and rest:
                rest = rest[1:]  # the duration
            if head == "env":
                while rest and _ASSIGNMENT.match(rest[0]):
                    rest = rest[1:]
            words = rest
        else:
            return words
    return words


def _after_options(words: list[str], value_options: frozenset[str]) -> list[str]:
    index = 0
    while index < len(words) and words[index].startswith("-") and len(words[index]) > 1:
        index += 2 if words[index] in value_options else 1
    return words[index:]


def _judge(words: list[str], body: Optional[str], depth: int) -> Optional[str]:
    if depth > _MAX_DEPTH:
        return None
    for word in words:  # $(…) and `…` inside a word run a command of their own
        if "$(" in word or "`" in word:
            for match in _SUBSHELL.finditer(word[:4000]):
                label = _scan_shell(match.group(1) or match.group(2), depth + 1)
                if label:
                    return label
    words = _unwrap(words)
    if not words:
        return None
    program, args = _program(words[0]), words[1:]

    if program == "himalaya":
        plain = _positionals(args, _HIMALAYA_VALUE_OPTIONS)
        if plain[:1] == ["send"] or (len(plain) > 1 and (
                (plain[0] in ("message", "messages", "msg") and plain[1] in _SEND_VERBS)
                or (plain[0] in ("template", "tpl") and plain[1] == "send"))):
            return "himalaya send"
        return None
    if program in _SENDMAILS:
        return None if any(_SENDMAIL_QUERY.match(arg) for arg in args) else program
    if program == "swaks":
        return None if any(arg in ("--version", "--help", "--support", "--dump") for arg in args) else "swaks"
    if program in _MAILS:
        if any(arg in ("-f", "-u", "-H", "-e") for arg in args):
            return None  # reading a mailbox
        sending = any(arg == "-t" or arg.startswith(("-s", "-b", "-c", "-r")) for arg in args)
        return "mail" if sending or _positionals(args, _MAIL_VALUE_OPTIONS) else None
    if program in _MUTTS:
        if any(arg in ("-v", "-vv", "-D", "-Q", "-y", "-Z", "-R", "-z", "-p", "-f") for arg in args):
            return None
        sending = any(arg.startswith(("-s", "-H")) for arg in args)
        return "mutt" if sending or _positionals(args, _MUTT_VALUE_OPTIONS) else None
    if program in ("curl", "wget", "http", "https", "xh"):
        return _judge_http(program, args)
    if program in _GMAIL_CLIS:
        plain = _positionals(args)
        if (program == "gmail" or "gmail" in plain) and any(word in _SEND_VERBS for word in plain):
            return "Gmail send"
        return None
    if program == "agentmail":
        return "agentmail send" if any(word in _SEND_VERBS for word in _positionals(args)) else None
    if program == "aws":
        plain = _positionals(args, frozenset({"--profile", "--region", "--endpoint-url", "--output"}))
        return "AWS SES" if len(plain) > 1 and plain[0] in ("ses", "sesv2") and plain[1].startswith("send-") else None
    if program == "osascript":
        script = " ".join(args) + ("\n" + body if body else "")
        if re.search(r'application\s+"Mail"', script, re.IGNORECASE) and re.search(r"\bsend\b", script, re.IGNORECASE):
            return "Apple Mail script"
        return None
    if program in ("powershell", "pwsh", "powershell.exe"):
        return "PowerShell mail" if "send-mailmessage" in (" ".join(args) + (body or "")).lower() else None
    if program in _SHELLS or program == "su":
        for index, arg in enumerate(args[:-1]):
            if arg.startswith("-") and not arg.startswith("--") and "c" in arg:
                label = _scan_shell(args[index + 1], depth + 1)
                if label:
                    return label
        return _scan_shell(body, depth + 1) if body and program != "su" else None
    if program == "eval":
        return _scan_shell(" ".join(args), depth + 1)
    if program == "ssh":
        rest = _after_options(args, _SSH_VALUE_OPTIONS)[1:]  # after the host
        return _scan_shell(" ".join(rest), depth + 1) if rest else None
    if program in _CONTAINERS:
        if not any(arg in ("exec", "run") for arg in args[:3]):
            return None
        for index, arg in enumerate(args):
            name = _program(arg)
            if name in _SENDMAILS or name in _MAILS or name in _MUTTS or name in _SHELLS or name in ("himalaya", "swaks") or _INTERPRETER.match(name):
                return _judge(args[index:], body, depth + 1)
        return None
    if _INTERPRETER.match(program):
        for index, arg in enumerate(args[:-1]):
            if arg in ("-c", "-e", "--eval", "-r", "-p", "--print"):
                label = _scan_code(args[index + 1])
                if label:
                    return label
        if body:
            label = _scan_code(body)
            if label:
                return label
        plain = _positionals(args)
        if "gmail" in plain and any(word in _SEND_VERBS for word in plain[plain.index("gmail"):]):
            return "Gmail send"
    return None


def _judge_http(program: str, args: list[str]) -> Optional[str]:
    joined = " ".join(args)
    if program == "curl" and re.search(r"\bsmtps?://", joined, re.IGNORECASE):
        return "curl over SMTP"
    match = _API_SEND_ONLY.search(joined)
    if match:
        return f"mail API ({match.group(0).split('/')[0].lower()})"
    match = _API_SEND_WITH_BODY.search(joined)
    if not match:
        return None
    posting = False
    for index, arg in enumerate(args):
        if arg.startswith(_HTTP_BODY_OPTIONS) or arg in ("-d", "-F", "-T") or (arg.startswith(("-d", "-F")) and not arg.startswith("--")):
            posting = True
        elif arg in ("-X", "--request", "--method") and index + 1 < len(args) and args[index + 1].upper() in ("POST", "PUT"):
            posting = True
        elif program in ("http", "https", "xh") and (arg.upper() == "POST" or ("=" in arg and "://" not in arg)):
            posting = True
    return f"mail API ({match.group(0).split('/')[0].lower()})" if posting else None


# --- scripts ---------------------------------------------------------------------------------------

def _scan_code(code: str) -> Optional[str]:
    for label, mention, call in _CODE_RULES:
        if mention.search(code) and (call is None or call.search(code)):
            return label
    match = _API_SEND_ONLY.search(code)
    if match is None and _POSTING_CODE.search(code):
        match = _API_SEND_WITH_BODY.search(code)
    if match:
        return f"mail API ({match.group(0).split('/')[0].lower()})"
    if _SPAWNS.search(code) and _MAILER_IN_CODE.search(code):
        return "mailer started from a script"
    return None
