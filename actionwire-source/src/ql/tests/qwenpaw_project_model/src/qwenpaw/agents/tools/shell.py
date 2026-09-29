import asyncio
import subprocess


def _collapse_embedded_newlines(command):
    return command.replace("\\\n", "").replace("\n", " ")


def _collapse_embedded_newline(command):
    return command.replace("\n", " ")


def _execute_subprocess_sync(command, cwd):
    return subprocess.Popen(command, cwd=cwd, shell=True)


async def execute_shell_command(command, cwd=None):
    collapsed = _collapse_embedded_newlines(command)
    await asyncio.to_thread(_execute_subprocess_sync, collapsed, cwd)
    return await asyncio.create_subprocess_shell(collapsed, cwd=cwd)


async def unrelated_shell_helper(command):
    return await asyncio.create_subprocess_shell(command)
