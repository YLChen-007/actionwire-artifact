class ToolGuardMixin:
    async def _decide_guard_action(self, tool_call):
        tool_name = str(tool_call.get("name", ""))
        tool_input = tool_call.get("input", {})
        guarded = self._tool_guard_engine.is_guarded(tool_name)
        guard_result = self._tool_guard_engine.guard(
            tool_name,
            tool_input,
            only_always_run=not guarded,
        )
        if guard_result is None or not guard_result.findings:
            return None
        return guard_result
