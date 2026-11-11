#!/usr/bin/env python3
"""Run Hermes's catalog validator (the checks behind ``hermes plugins validate``) on this plugin.

    HERMES_AGENT_DIR=/path/to/hermes-agent /path/to/hermes-agent/venv/bin/python tests/hermes_validate.py [plugin dir]

Prints every check and exits 1 when one fails or when the security scan is not "safe".
Exits 0 with "skipped" when Hermes is not importable.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    agent_dir = os.environ.get("HERMES_AGENT_DIR")
    if agent_dir:
        sys.path.insert(0, agent_dir)
    try:
        from hermes_cli.plugin_validate import validate_plugin_dir
    except ImportError:
        print("skipped: Hermes is not importable (set HERMES_AGENT_DIR and use its Python)")
        return 0
    plugin_dir = Path(argv[1] if len(argv) > 1 else Path(__file__).resolve().parent.parent).resolve()
    report = validate_plugin_dir(plugin_dir)
    failed = 0
    for name, passed, detail in report.checks:
        print(f"{'ok  ' if passed else 'FAIL'} {name}: {detail}")
        failed += 0 if passed else 1
        if name == "security scan" and detail != "safe":
            failed += 1
    for warning in getattr(report, "warnings", ()):
        print(f"warn {warning}")
    print("validation passed" if not failed and report.ok else "validation FAILED")
    return 0 if not failed and report.ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
