def _run_browser_command(task_id, command, args, timeout=None):
    return task_id, command, args, timeout


def browser_dispatch_sensitive(session, url, expression, snapshot_flags, timeout):
    _run_browser_command(session, "open", [url], timeout=timeout)
    _run_browser_command(session, "eval", [expression], timeout=timeout)
    _run_browser_command(session, "snapshot", snapshot_flags, timeout=timeout)


def browser_dispatch_fixed(session):
    _run_browser_command(session, "open", ["about:blank"], timeout=10)
    _run_browser_command(session, "eval", ["window.location.href"], timeout=10)
