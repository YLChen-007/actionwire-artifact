class Edit:
    def execute(self, args):
        path = args.get("path", "")
        absolute_path = self._resolve_path(path)
        return open(absolute_path, "w")

    def _resolve_path(self, path):
        return path
