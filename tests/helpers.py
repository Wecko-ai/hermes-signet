"""Load the plugin directory as a package, the way Hermes does, without Hermes."""
from __future__ import annotations

import importlib.util
import socketserver
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "signet_under_test"


def load():
    if PACKAGE in sys.modules:
        return sys.modules[PACKAGE]
    spec = importlib.util.spec_from_file_location(PACKAGE, ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[PACKAGE] = module
    spec.loader.exec_module(module)
    return module


def module(name: str):
    load()
    return importlib.import_module(f"{PACKAGE}.{name}")


class FakeContext:
    """The slice of Hermes's plugin context that Signet uses."""

    def __init__(self, **settings):
        self.settings = settings
        self.cron = None
        self.tools = {}
        self.hooks = {}
        self.commands = {}

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def current_cron_execution(self):
        return self.cron

    def register_tool(self, name, toolset, schema, handler, **kwargs):
        self.tools[name] = handler

    def register_hook(self, name, callback, **kwargs):
        self.hooks[name] = callback

    def register_command(self, name, handler, **kwargs):
        self.commands[name] = handler


class _Session(socketserver.StreamRequestHandler):
    def handle(self):
        def say(line):
            self.wfile.write(line.encode() + b"\r\n")

        say("220 sink ready")
        sender, recipients, data = "", [], None
        while True:
            line = self.rfile.readline()
            if not line:
                return
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            verb = text[:4].upper()
            if verb in ("EHLO", "HELO"):
                say("250 sink")
            elif verb == "MAIL":
                sender = text.partition(":")[2].split()[0].strip("<>")
                say("250 ok")
            elif verb == "RCPT":
                recipients.append(text.partition(":")[2].strip().strip("<>"))
                say("250 ok")
            elif verb == "DATA":
                say("354 go on")
                chunks = []
                while True:
                    part = self.rfile.readline()
                    if part in (b".\r\n", b".\n", b""):
                        break
                    chunks.append(part[1:] if part.startswith(b"..") else part)
                data = b"".join(chunks)
                self.server.received.append({"from": sender, "to": list(recipients), "data": data})
                say("250 queued")
            elif verb == "QUIT":
                say("221 bye")
                return
            else:
                say("250 ok")


class SmtpSink(socketserver.ThreadingTCPServer):
    """A tiny SMTP server on 127.0.0.1 that keeps what it receives. For tests only."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Session)
        self.received = []
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self):
        return self.server_address[1]

    def close(self):
        self.shutdown()
        self.server_close()
