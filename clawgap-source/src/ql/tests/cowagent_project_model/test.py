import requests
import subprocess

from agent.tools.edit import edit  # noqa: F401
from agent.tools.read import read  # noqa: F401


class BaseTool:
    def execute(self, args):
        raise NotImplementedError

    def execute_tool(self, args):
        return self.execute(args)

    def _execute_tool(self, args):
        return self.execute_tool(args)


class Bash(BaseTool):
    def execute(self, args):
        command = args.get("command", "")
        return subprocess.run(command, shell=True)


class BrowserTool(BaseTool):
    def execute(self, args):
        action = args.get("action", "")
        handler = self._ACTION_MAP.get(action)
        return handler(self, args)

    def _do_navigate(self, args):
        url = args.get("url", "")
        service = BrowserService()
        return service.navigate(url)

    def _do_unrelated(self, value):
        return value

    _ACTION_MAP = {"navigate": _do_navigate}


class BrowserService:
    def _submit(self, callback, *args):
        return callback(*args)

    def navigate(self, url):
        return self._submit(self._do_navigate, url)

    def _do_navigate(self, url):
        return page.goto(url)


class Vision(BaseTool):
    def execute(self, args):
        url = args.get("url", "")
        return requests.get(url)


class InfrastructureFileOperation:
    def execute(self, args):
        return open(args.get("path", ""), "w")


def unrelated_callback(value):
    return value
