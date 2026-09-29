from pathlib import Path


class FunctionTool:
    async def call(self, context, **kwargs):
        raise NotImplementedError


def _resolve_tool_path(path, *, local_env=True, umo="fixture"):
    return str(Path(path).resolve())


def _is_path_within_allowed_roots(path, *, umo="fixture", allowed_roots=()):
    return bool(path) and all(path != blocked for blocked in allowed_roots)


def _normalize_rw_path(path, *, restricted=True, local_env=True, umo="fixture"):
    normalized_path = _resolve_tool_path(path, local_env=local_env, umo=umo)
    if restricted and not _is_path_within_allowed_roots(
        normalized_path, umo=umo, allowed_roots=("blocked",)
    ):
        raise PermissionError
    return normalized_path


async def read_file_tool_result(path):
    return await _probe_local_file(path)


async def _probe_local_file(path):
    def _run():
        return open(path, "rb")

    return await to_thread(_run)


class FileReadTool(FunctionTool):
    async def call(self, context, path):
        normalized_path = _normalize_rw_path(path)
        return await read_file_tool_result(normalized_path)


class FileWriteTool(FunctionTool):
    async def call(self, context, path, content):
        normalized_path = _normalize_rw_path(path)
        return await sb.fs.write_file(path=normalized_path, content=content)


class FileEditTool(FunctionTool):
    async def call(self, context, path, old, new):
        normalized_path = _normalize_rw_path(path)
        return await sb.fs.edit_file(
            path=normalized_path, old_string=old, new_string=new
        )


class LocalFileSystemComponent:
    async def write_file(self, path, content):
        def _run():
            with open(path, "w") as handle:
                handle.write(content)

        return await asyncio.to_thread(_run)

    async def edit_file(self, path, old_string, new_string):
        def _run():
            with open(path, "w") as handle:
                handle.write(new_string)

        return await asyncio.to_thread(_run)


class LocalShellComponent:
    async def exec(self, command):
        def _run():
            return subprocess.run(command, shell=True)

        return await asyncio.to_thread(_run)


class LocalPythonComponent:
    async def exec(self, code):
        def _run():
            return subprocess.run(["python", "-c", code])

        return await asyncio.to_thread(_run)


class InfrastructureOperation:
    async def call(self, context, path):
        return open(path, "w")
