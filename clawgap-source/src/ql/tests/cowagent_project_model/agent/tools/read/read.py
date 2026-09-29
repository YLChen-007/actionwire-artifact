class BaseTool:
    def execute_tool(self, args):
        return self.execute(args)


class Read(BaseTool):
    def execute(self, args):
        path = args.get("path", "")
        absolute_path = self._resolve_path(path)
        return open(absolute_path, "r")

    def _resolve_path(self, path):
        return normalize_path(path)

    def _resolve_paths(self, path):
        return normalize_path(path)


def normalize_path(path):
    return path
