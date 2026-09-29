import asyncio

from nanobot.agent.tools.base import Tool


class ExecTool(Tool):
    async def execute(self, command, working_dir=None, **kwargs):
        guard_error = self._guard_command(command, working_dir)
        if guard_error:
            return guard_error
        return await asyncio.create_subprocess_shell(command, cwd=working_dir)

    def _guard_command(self, command, working_dir):
        if "blocked" in command:
            return "blocked"
        return None
