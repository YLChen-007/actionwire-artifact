import asyncio
import os
import shutil
from pathlib import Path

from nanobot.agent.tools.base import Tool


class ExecTool(Tool):
    async def execute(self, command, shell=None, login=None, **kwargs):
        env = {
            "HOME": os.environ.get("HOME", "/tmp"),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "TERM": os.environ.get("TERM", "dumb"),
        }
        shell_program = shell or shutil.which("bash") or "/bin/bash"
        effective_login = True if login is None else login
        if effective_login and Path(shell_program).name in {"bash", "zsh"}:
            return await asyncio.create_subprocess_exec(
                shell_program, "-l", "-c", command, env=env
            )
        return await asyncio.create_subprocess_exec(
            shell_program, "-c", command, env=env
        )
