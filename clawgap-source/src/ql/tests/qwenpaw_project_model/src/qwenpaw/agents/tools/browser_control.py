import subprocess


def _start_managed_browser(cdp_port):
    args = ["chrome", f"--remote-debugging-port={cdp_port}"]
    return subprocess.Popen(args)


async def browser_use(action, cdp_port=0):
    if action == "start":
        return _start_managed_browser(cdp_port)
    return None
