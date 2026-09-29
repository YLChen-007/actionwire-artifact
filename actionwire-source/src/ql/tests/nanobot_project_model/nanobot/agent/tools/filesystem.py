from nanobot.agent.tools.base import Tool
from pathlib import Path


def _resolve_path(path):
    return Path(path).expanduser().resolve()


def _resolve_paths(path):
    return Path(path).resolve()


class _FsTool(Tool):
    def _resolve(self, path):
        return _resolve_path(path)


class ReadFileTool(_FsTool):
    async def execute(self, path, **kwargs):
        return open(self._resolve(path), "r")
