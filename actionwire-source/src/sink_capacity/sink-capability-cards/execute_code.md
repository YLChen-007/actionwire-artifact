# execute_code(code: str, task_id: Optional[str] = None, enabled_tools: Optional[List[str]] = None) -> str

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-ab7c1f4004e5f0e5
api: 'execute_code(code: str, task_id: Optional[str] = None, enabled_tools: Optional[List[str]] = None) -> str'
api_family: execute_code
runtime:
  language: python
  ecosystem: project-source
  package: execute_code
  version: legacy-source-bound
capability_class: code-eval
normative_authority: capability-facts-only
bound_sinks: []
roles:
- role_id: code
  description: Legacy controlled role code.
  bindings:
  - expression: code
    caller_bindable: true
facets:
- facet_id: legacy-facet-5a9d3442
  capability: Arbitrary Python source code execution in a real OS subprocess spawned via subprocess.Popen.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-11e18f82
  capability: The subprocess is a full Python interpreter — import any module, use any built-in, call eval/exec/compile.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-0c195d2c
  capability: Spawn child processes from within the script via subprocess, os.system, os.popen, os.fork, etc.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-60e19c8d
  capability: Read and write arbitrary files on the host filesystem (subject to OS-level DAC permissions of the hermes-agent process user).
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-7496f122
  capability: In project mode (the default), the subprocess inherits the session's working directory — read/modify/exfiltrate any user project files.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-d0114eb8
  capability: In project mode, the subprocess uses the active virtualenv/conda Python — import all installed packages (pandas, torch, requests, cryptography, etc.).
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-49ee18c1
  capability: Make arbitrary outbound network connections (HTTP/HTTPS via requests/urllib, raw TCP/UDP sockets) from within the executed script.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-a935880c
  capability: The subprocess inherits all non-secret environment variables (PATH, HOME, LANG, SHELL, TERM, PYTHONPATH, etc.) — access local config, SSH agent sockets, OS credential helpers.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-e3fa35a9
  capability: 'Via the hermes_tools.py RPC stubs, the script can call back into hermes-agent tools: terminal (arbitrary shell commands), read_file, write_file, web_search, web_extract, search_files, patch.'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-60467d4c
  capability: The terminal RPC stub, when available, collapses the code-execution capability into full arbitrary shell-command execution with all attendant capabilities (subprocess chains, file ops, network ops, persistence).
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-28cb41fa
  capability: Stdout, stderr, and exit code are collected and returned to the caller; by default stdout is truncated to 2 MiB with a head+tail window.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-7a180b71
  capability: The script runs as a separate OS process with os.setsid (new process group on POSIX) — it can background itself, detach, or daemonize.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-6872f512
  capability: No per-process CPU/memory/disk/network resource limits are applied by the wrapper; the subprocess can consume host resources at will.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-16670647
  capability: On remote backends (Docker/SSH/Modal/Daytona), the script runs inside the terminal backend environment — the capability scope depends on that backend's isolation.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-323707cd
  role_id: null
  value: Project mode is the default execution mode — the subprocess CWD is the user's session working directory, not a temp directory.
  security_effect: Project mode is the default execution mode — the subprocess CWD is the user's session working directory, not a temp directory.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-d285fe58
  role_id: null
  value: sys.executable or the active venv Python is used to run the script; the choice depends on the configured mode.
  security_effect: sys.executable or the active venv Python is used to run the script; the choice depends on the configured mode.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-1cec7ed0
  role_id: null
  value: PYTHONPATH is set to include the hermes-agent root directory, making all repo modules importable by the executed script.
  security_effect: PYTHONPATH is set to include the hermes-agent root directory, making all repo modules importable by the executed script.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-3344afdd
  role_id: null
  value: stdin is DEVNULL; stdout and stderr are piped back to the parent process.
  security_effect: stdin is DEVNULL; stdout and stderr are piped back to the parent process.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-2d74435e
  role_id: null
  value: Timeout defaults to a configurable value (DEFAULT_TIMEOUT); if reached, the process group receives SIGTERM then SIGKILL.
  security_effect: Timeout defaults to a configurable value (DEFAULT_TIMEOUT); if reached, the process group receives SIGTERM then SIGKILL.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-c925dd09
  role_id: null
  value: The sandbox tool set (SANDBOX_ALLOWED_TOOLS) is applied only as an intersection with session-enabled tools; if no session tools match, the full allowed set is used as a fallback.
  security_effect: The sandbox tool set (SANDBOX_ALLOWED_TOOLS) is applied only as an intersection with session-enabled tools; if no session tools match, the full allowed set is used as a fallback.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-8bcd203d
  role_id: null
  value: RPC stubs for allowed tools are auto-generated and injected into the temp directory alongside the script.
  security_effect: RPC stubs for allowed tools are auto-generated and injected into the temp directory alongside the script.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-526a2adf
  role_id: null
  value: On POSIX, os.setsid runs in the child pre-exec — the script starts in a new session and process group.
  security_effect: On POSIX, os.setsid runs in the child pre-exec — the script starts in a new session and process group.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-d83be845
  role_id: null
  value: The executed script can `import hermes_tools` and call tool functions as plain Python functions; tool results are returned synchronously over the RPC channel.
  security_effect: The executed script can `import hermes_tools` and call tool functions as plain Python functions; tool results are returned synchronously over the RPC channel.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-04217913
  role_id: null
  value: No audit logging of individual operations within the executed script — only tool-call counts and final stdout/stderr/exit-code are captured.
  security_effect: No audit logging of individual operations within the executed script — only tool-call counts and final stdout/stderr/exit-code are captured.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: See the source-owned legacy card for the original benign example.
  capability_edge: See the source-owned legacy card for the original capability-edge example.
provenance:
- source-owned legacy capability card
```
