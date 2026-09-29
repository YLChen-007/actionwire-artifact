import requests
import subprocess
import asyncio

from tools.environments.managed_modal import ManagedModalEnvironment  # noqa: F401
from tools.terminal_tool import terminal_tool  # noqa: F401
from tools import approval, browser_camofox, browser_tool, delivery  # noqa: F401


def fixed_url_tainted_body(payload):
    return requests.post("https://fixed.example/v1", json=payload)


def positional_get_url(url):
    return requests.get(url)


def positional_post_url(url):
    return requests.post(url, json={"fixed": True})


def keyword_post_url(url):
    return requests.post(url=url, json={"fixed": True})


def positional_request_url(url):
    return requests.request("POST", url, json={"fixed": True})


def keyword_request_url(url):
    return requests.request(method="POST", url=url, json={"fixed": True})


def non_http_argument(command, timeout):
    return subprocess.run(command, timeout=timeout)


def process_controls(command, cwd, env, timeout):
    subprocess.Popen(command, cwd=cwd, env=env)
    subprocess.run(command, cwd=cwd, env=env, timeout=timeout)


async def asyncio_process_controls(command, cwd, env, timeout):
    await asyncio.create_subprocess_exec("sh", "-c", command, cwd=cwd, env=env)
    await asyncio.create_subprocess_shell(command, cwd=cwd, env=env)


def receiver_sensitive(path, encoding):
    return path.read_text(encoding=encoding)


def builtin_open_sensitive(path, encoding):
    return open(path, "r", encoding=encoding)


def eval_sensitive(code, globals_dict):
    return eval(code, globals_dict)


def execute_code_sensitive(runner, code, task_id):
    return runner.execute_code(code, task_id=task_id)


def git_loader_sensitive(repo_path, clone_url, branch, file_filter):
    return GitLoader(repo_path, clone_url, branch, file_filter=file_filter)


def exa_sensitive(client, urls, text):
    return client.get_contents(urls, text=text)


async def firecrawl_sensitive(client, url, formats):
    return await asyncio.to_thread(client.scrape, url=url, formats=formats)


async def parallel_sensitive(client, urls, full_content):
    return await client.beta.extract(urls=urls, full_content=full_content)
