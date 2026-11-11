"""Signet: an email leaves a Hermes agent only with a person's seal on that exact message."""
from __future__ import annotations

from . import schemas
from .plugin import Signet

__version__ = "0.1.0"


def register(ctx) -> None:
    signet = Signet(ctx)
    ctx.register_tool(name=schemas.SEND_TOOL, toolset="signet", schema=schemas.SEND_MAIL,
                      handler=signet.send_mail, emoji="✉️")
    ctx.register_tool(name=schemas.OUTBOX_TOOL, toolset="signet", schema=schemas.OUTBOX,
                      handler=signet.outbox_tool, emoji="📮")
    ctx.register_hook("pre_tool_call", signet.pre_tool_call)
    ctx.register_hook("pre_approval_request", signet.pre_approval_request)
    ctx.register_hook("post_approval_response", signet.post_approval_response)
    ctx.register_command("signet", signet.command,
                         description="Emails waiting for your seal: status, show, send, drop, log",
                         args_hint="[show|send|drop CODE | log]")
