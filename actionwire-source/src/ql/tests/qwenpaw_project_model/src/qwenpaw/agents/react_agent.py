from qwenpaw.agents.tools.browser_control import browser_use
from qwenpaw.agents.tools.make_skill_tools import materialize_skill
from qwenpaw.agents.tools.shell import execute_shell_command


class QwenPawAgent:
    def register_memory_tools(self):
        memory_tools = self.memory_manager.list_memory_tools()
        for tool_fn in memory_tools:
            self.toolkit.register_tool_function(tool_fn)


def _create_toolkit(effective_skills):
    tool_functions = {
        "execute_shell_command": execute_shell_command,
        "browser_use": browser_use,
        **(
            {"materialize_skill": materialize_skill}
            if "make-skill" in effective_skills
            else {}
        ),
    }
    return tool_functions


async def _acting(tool_call):
    return tool_call
