#!/usr/bin/env python3
"""Integration test: Signet against the REAL Hermes plugin manager and approval gate.

No model call, no network, nothing is sent: the default ``outbox`` transport only writes .eml files.

Usage (use a Python that can import Hermes, e.g. the venv of the checkout):

    HERMES_AGENT_DIR=/path/to/hermes-agent \\
    HERMES_HOME=/path/to/throwaway-home \\
    /path/to/hermes-agent/venv/bin/python tests/hermes_integration.py [scenario ...]

* ``HERMES_AGENT_DIR``: the Hermes checkout (optional when ``hermes_cli`` is already importable).
* ``HERMES_HOME``: a THROWAWAY Hermes home. The script writes ``config.yaml`` and
  ``plugins/signet`` (a symlink to this repository) and ``plugin-data/signet`` there, and restores
  config.yaml afterwards. When unset, a temporary directory is used. Never point it at a real home.

Each scenario runs in its own subprocess, because the things it flips (YOLO mode, approvals.mode,
the interactive flag) are read by Hermes once per process or cached.

The agent loop's path is used: ``model_tools.handle_function_call`` -> ``pre_tool_call`` hooks
-> ``tools.approval.request_tool_approval`` -> the approval callback standing in for the person
-> tool handler. Scenario E only calls the pre-dispatch function, so no terminal command ever runs.

Exit code: 0 when every scenario passes (or Hermes is not importable: "skipped"), 1 otherwise.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCENARIOS = ("A", "B", "C", "D", "E", "F", "G")
MAIL = {
    "to": ["Ada Lovelace <ada@example.org>"],
    "subject": "Integration test mail",
    "body": "Hello Ada,\nthis is the body of the integration test.\n",
    "from": "Signet Test <signet-test@example.org>",
}

# Hermes variables that decide who can answer an approval: start every scenario from a clean slate.
_SCRUB = ("HERMES_INTERACTIVE", "HERMES_YOLO_MODE", "HERMES_EXEC_ASK", "HERMES_GATEWAY_SESSION",
          "HERMES_SESSION_PLATFORM", "HERMES_SESSION_KEY", "HERMES_CRON_SESSION",
          "HERMES_SINGLE_QUERY_SESSION", "HERMES_SAFE_MODE")


# ---------------------------------------------------------------------------------------------
# Worker side: one scenario, inside a process whose environment the parent prepared.
# ---------------------------------------------------------------------------------------------
class Check:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.evidence: list[str] = []

    def ok(self, condition: bool, message: str) -> bool:
        if not condition:
            self.failures.append(message)
        return condition

    def note(self, text: str) -> None:
        self.evidence.append(text)


def _ledger(home: Path) -> list[dict]:
    path = home / "plugin-data" / "signet" / "ledger.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _emls(home: Path) -> list[Path]:
    return sorted((home / "plugin-data" / "signet" / "outbox").glob("*.eml"))


def _pending(home: Path) -> list[Path]:
    return sorted((home / "plugin-data" / "signet" / "pending").glob("*.json"))


def _worker(name: str) -> dict:
    home = Path(os.environ["HERMES_HOME"])
    agent_dir = os.environ.get("HERMES_AGENT_DIR")
    if agent_dir:
        sys.path.insert(0, agent_dir)

    check = Check()
    from email import message_from_bytes, policy

    import model_tools
    from hermes_cli.plugins import (_dispatch_pre_tool_call_hooks, discover_plugins,
                                    get_plugin_command_handler, get_plugin_manager,
                                    resolve_plugin_command_result)
    from hermes_cli.plugin_command_dispatch import invoke_plugin_command
    from tools.terminal_tool import set_approval_callback

    discover_plugins()
    manager = get_plugin_manager()
    loaded = manager._plugins.get("signet")
    check.ok(loaded is not None and loaded.enabled and not loaded.error,
             f"plugin not loaded by the plugin manager: {getattr(loaded, 'error', 'absent')}")
    if not check.ok(get_plugin_command_handler("signet") is not None, "/signet is not registered"):
        return _report(check)
    check.ok("signet_send_mail" in model_tools.get_all_tool_names(), "tool signet_send_mail not registered")

    # Observers: what the approval callback received, and every post_approval_response Hermes fires.
    asked: list[dict] = []
    responses: list[dict] = []
    answer = {"choice": "deny"}

    def person(command, description, **kwargs):
        asked.append({"command": command, "description": description, "kwargs": kwargs})
        return answer["choice"]

    def spy(**kwargs):
        responses.append(kwargs)

    manager._hooks.setdefault("post_approval_response", []).append(spy)  # private dict: test-only spy
    set_approval_callback(person)

    def send(args=None):
        raw = model_tools.handle_function_call("signet_send_mail", dict(args or MAIL), task_id="t1",
                                               session_id="s1", tool_call_id="c1")
        try:
            return raw, json.loads(raw)
        except ValueError:
            return raw, {}

    def slash(raw_args: str) -> str:
        handler = get_plugin_command_handler("signet")
        return str(resolve_plugin_command_result(
            invoke_plugin_command(handler, raw_args, source=None, session_id="s1", session_key="s1", platform="cli")))

    def mail_matches(path: Path) -> bool:
        msg = message_from_bytes(path.read_bytes(), policy=policy.default)
        text = msg.get_body(("plain",)).get_content().replace("\r\n", "\n")
        return ("ada@example.org" in str(msg["To"]) and msg["Subject"] == MAIL["subject"]
                and text.strip() == MAIL["body"].strip())

    if name == "A":
        answer["choice"] = "once"
        raw, result = send()
        check.ok(result.get("status") == "written", f"status {result.get('status')!r}, expected 'written': {raw[:300]}")
        emls = _emls(home)
        check.ok(len(emls) == 1, f"{len(emls)} .eml in the outbox, expected 1")
        check.ok(bool(emls) and mail_matches(emls[0]), "the .eml does not match To/Subject/body of the arguments")
        sent = [e for e in _ledger(home) if e.get("event") == "sent"]
        check.ok(len(sent) == 1 and sent[0].get("sealed_by") == "approval:once", f"ledger sent entries: {sent}")
        check.ok(not _pending(home), f"pending/ not empty after a send: {_pending(home)}")
        check.ok(len(asked) == 1, f"approval callback asked {len(asked)} times, expected 1")
        mine = [r for r in responses if "signet:" in str(r.get("pattern_key"))]
        check.ok(len(mine) == 1 and str(mine[0].get("pattern_key")).startswith("plugin_rule:signet:")
                 and mine[0].get("choice") == "once", f"post_approval_response seen: {responses}")
        if asked:
            check.note("callback command=%r" % asked[0]["command"])
            check.note("callback description=\n" + asked[0]["description"])
            check.note("callback kwargs=%r" % asked[0]["kwargs"])
        if mine:
            check.note("post_approval_response kwargs=%r" % {k: v for k, v in mine[0].items()})
        summary = f"status={result.get('status')} eml={len(emls)} ledger={[e['event'] + ':' + str(e.get('sealed_by')) for e in _ledger(home)]}"

    elif name == "B":
        answer["choice"] = "deny"
        raw, result = send()
        check.ok("BLOCKED" in raw, f"tool result is not Hermes's BLOCKED text: {raw[:300]}")
        check.ok(not _emls(home), "an .eml was written after a deny")
        events = [e.get("event") for e in _ledger(home)]
        check.ok("denied" in events and "sent" not in events, f"ledger events {events}")
        kept = [json.loads(p.read_text(encoding="utf-8")) for p in _pending(home)]
        check.ok(len(kept) == 1 and kept[0].get("state") == "denied",
                 f"a denied draft should be kept as 'denied' for the person: {[k.get('state') for k in kept]}")
        summary = f"result={raw[:160]!r} ledger={events}"

    elif name in ("C", "D"):
        # C: HERMES_YOLO_MODE=1 (the CLI --yolo switch); D: approvals.mode: off in config.yaml.
        answer["choice"] = "once"  # must never be asked
        raw, result = send()
        check.ok(not asked, f"the person was asked although the gate should be bypassed ({len(asked)}x)")
        check.ok(result.get("status") == "held", f"status {result.get('status')!r}, expected 'held': {raw[:300]}")
        check.ok(not _emls(home), "an .eml was written without a person's seal")
        pend = _pending(home)
        check.ok(len(pend) == 1, f"{len(pend)} files in pending/, expected 1")
        code = result.get("code", "")
        # The first /signet send reads the email back in full and sends nothing; the second one seals it.
        first = slash(f"send {code}")
        check.ok("Nothing was sent yet" in first and MAIL["subject"] in first and not _emls(home),
                 f"the first /signet send should only show the email: {first[:200]!r}")
        out = slash(f"send {code}")
        emls = _emls(home)
        check.ok(len(emls) == 1 and mail_matches(emls[0]), f"after /signet send: {len(emls)} .eml ({out[:200]!r})")
        sent = [e for e in _ledger(home) if e.get("event") == "sent"]
        check.ok(len(sent) == 1 and sent[0].get("sealed_by") == "command:/signet send", f"ledger sent entries: {sent}")
        check.ok(not _pending(home), "pending/ not empty after /signet send")
        check.note(f"held code={code}; /signet send replied {out[:120]!r}")
        summary = f"asked={len(asked)} status={result.get('status')} pending={len(pend)} -> /signet send: eml={len(emls)} sealed_by={[e.get('sealed_by') for e in sent]}"

    elif name == "E":
        block, _ = _dispatch_pre_tool_call_hooks("terminal", {"command": "echo hi | himalaya message send"},
                                                 task_id="t1", session_id="s1", tool_call_id="c1")
        check.ok(isinstance(block, str) and block.startswith("BLOCKED by Signet"), f"himalaya not blocked by Signet: {block!r}")
        ok_block, _ = _dispatch_pre_tool_call_hooks("terminal", {"command": "ls -la"},
                                                    task_id="t1", session_id="s1", tool_call_id="c2")
        check.ok(ok_block is None, f"a harmless command was blocked: {ok_block!r}")
        events = [(e.get("event"), e.get("mailer")) for e in _ledger(home)]
        check.ok(("blocked", "himalaya send") in events, f"ledger lacks the blocked entry: {events}")
        check.ok(not asked, "the person was asked for a guard block")
        summary = f"himalaya -> {str(block)[:90]!r}; ls -la -> {ok_block!r}; ledger={events}"

    elif name == "F":
        answer["choice"] = "once"  # must never be asked: nobody is there
        raw, result = send()
        check.ok(not asked, "the approval callback was reached in a non-interactive process")
        check.ok(not _emls(home), "an .eml was written with nobody to approve")
        check.ok(raw.startswith('{"error"') and "BLOCKED" in raw, f"model-visible result is not a BLOCKED error: {raw[:300]}")
        check.note("model sees: " + raw)
        check.note("pending after: %s; ledger: %s" % ([p.name for p in _pending(home)], [e.get("event") for e in _ledger(home)]))
        held = [json.loads(p.read_text(encoding="utf-8")) for p in _pending(home)]
        check.ok(len(held) == 1 and "nobody could be asked" in held[0].get("reason", ""),
                 f"the draft is not held with an honest reason: {[h.get('reason') for h in held]}")
        summary = f"model sees {raw[:150]!r}; pending={len(_pending(home))}"

    elif name == "G":
        # "Always allow" must cover one showing only: the same email sent again is asked about again.
        answer["choice"] = "always"
        _, first = send()
        _, second = send()
        check.ok(first.get("status") == "written" and second.get("status") == "written",
                 f"statuses {first.get('status')!r}, {second.get('status')!r}, expected written twice")
        check.ok(len(asked) == 2, f"the person was asked {len(asked)} time(s) for two sends, expected 2")
        check.ok(len(_emls(home)) == 2 or len({e.get('message_id') for e in _ledger(home) if e.get('event') == 'sent'}) == 2,
                 "two sends did not produce two sealed messages")
        summary = f"asked={len(asked)} statuses={[first.get('status'), second.get('status')]}"
    else:
        raise SystemExit(f"unknown scenario {name}")

    return _report(check, summary)


def _report(check: Check, summary: str = "") -> dict:
    return {"ok": not check.failures, "failures": check.failures, "evidence": check.evidence, "summary": summary}


# ---------------------------------------------------------------------------------------------
# Parent side: prepare the home, run each scenario in a fresh process, print one line each.
# ---------------------------------------------------------------------------------------------
CONFIG_BASE = """\
plugins:
  enabled:
    - signet
  entries:
    signet:
      settings:
        transport: outbox
        from_address: "Signet Test <signet-test@example.org>"
approvals:
  mode: "{mode}"
"""

PLAN = {  # scenario -> (approvals.mode, extra environment)
    "A": ("manual", {"HERMES_INTERACTIVE": "1"}),
    "B": ("manual", {"HERMES_INTERACTIVE": "1"}),
    "C": ("manual", {"HERMES_INTERACTIVE": "1", "HERMES_YOLO_MODE": "1"}),
    "D": ("off", {"HERMES_INTERACTIVE": "1"}),
    "E": ("manual", {"HERMES_INTERACTIVE": "1"}),
    "F": ("manual", {}),
    "G": ("manual", {"HERMES_INTERACTIVE": "1"}),
}
TITLES = {
    "A": "person answers once -> written, one .eml, ledger sent/approval:once",
    "B": "person answers deny -> BLOCKED, no .eml, ledger denied, draft kept as denied",
    "C": "YOLO -> held (not sent); /signet send CODE shows it, the second one sends, sealed_by command",
    "D": "approvals.mode off -> held (not sent); /signet send CODE twice -> .eml",
    "E": "guard blocks himalaya send in terminal, lets ls -la through",
    "F": "no interactive user / gateway / cron -> Hermes fails closed, nothing sent, draft held",
    "G": "an 'always allow' answer covers one showing: the next send is asked about again",
}


def _find_hermes(agent_dir: str | None) -> bool:
    probe = "import sys\nif %r: sys.path.insert(0, %r)\nimport hermes_cli.plugins, model_tools" % (agent_dir, agent_dir)
    done = subprocess.run([sys.executable, "-I", "-c", probe], capture_output=True, text=True,
                          env={**os.environ, "HERMES_HOME": os.environ["HERMES_HOME"]}, cwd=tempfile.gettempdir())
    return done.returncode == 0


def main(argv: list[str]) -> int:
    if len(argv) >= 3 and argv[1] == "--worker":
        print("RESULT:" + json.dumps(_worker(argv[2])))
        return 0

    own_temp = None
    if not os.environ.get("HERMES_HOME"):
        own_temp = tempfile.mkdtemp(prefix="signet-hermes-home-")
        os.environ["HERMES_HOME"] = own_temp
    home = Path(os.environ["HERMES_HOME"]).resolve()
    agent_dir = os.environ.get("HERMES_AGENT_DIR") or ""
    if not _find_hermes(agent_dir or None):
        print(f"skipped: Hermes is not importable with {sys.executable} (set HERMES_AGENT_DIR and use its Python)")
        return 0

    wanted = [s.upper() for s in argv[1:]] or list(SCENARIOS)
    config = home / "config.yaml"
    backup = config.read_bytes() if config.exists() else None
    link = home / "plugins" / "signet"
    link_existed = link.is_symlink() or link.exists()
    failed = 0
    try:
        (home / "plugins").mkdir(parents=True, exist_ok=True)
        if not link_existed:
            link.symlink_to(REPO, target_is_directory=True)
        for name in wanted:
            mode, extra = PLAN[name]
            config.write_text(CONFIG_BASE.format(mode=mode), encoding="utf-8")
            shutil.rmtree(home / "plugin-data" / "signet", ignore_errors=True)
            env = {k: v for k, v in os.environ.items() if k not in _SCRUB}
            env.update(extra, HERMES_HOME=str(home), PYTHONDONTWRITEBYTECODE="1")
            if agent_dir:
                env["HERMES_AGENT_DIR"] = agent_dir
            done = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--worker", name],
                                  capture_output=True, text=True, env=env, cwd=tempfile.gettempdir(), timeout=180)
            line = next((ln for ln in done.stdout.splitlines() if ln.startswith("RESULT:")), "")
            if not line:
                failed += 1
                print(f"FAIL {name}: {TITLES[name]}\n     worker crashed (exit {done.returncode}):\n{done.stderr[-1500:]}")
                continue
            res = json.loads(line[len("RESULT:"):])
            if res["ok"]:
                print(f"PASS {name}: {TITLES[name]}\n     {res['summary']}")
            else:
                failed += 1
                print(f"FAIL {name}: {TITLES[name]}\n     {res['summary']}")
                for failure in res["failures"]:
                    print(f"     - {failure}")
            if os.environ.get("SIGNET_TEST_VERBOSE", "1") != "0":
                for note in res["evidence"]:
                    print("     | " + note.replace("\n", "\n     | "))
    finally:
        if backup is None:
            config.unlink(missing_ok=True)
        else:
            config.write_bytes(backup)
        if not link_existed:
            link.unlink(missing_ok=True)
        if own_temp:
            shutil.rmtree(own_temp, ignore_errors=True)
    print(f"{len(wanted) - failed}/{len(wanted)} scenarios passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
