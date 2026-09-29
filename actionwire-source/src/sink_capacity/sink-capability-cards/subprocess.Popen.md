# subprocess.Popen

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-302ea5b2bac8a4d8
api: subprocess.Popen
api_family: subprocess.Popen
runtime:
  language: python
  ecosystem: python-runtime
  package: subprocess
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
- role_id: environment
  description: Legacy controlled role environment.
  bindings:
  - expression: env
    caller_bindable: true
- role_id: executable
  description: Legacy controlled role executable.
  bindings:
  - expression: executable
    caller_bindable: true
- role_id: shell-mode
  description: Legacy controlled role shell-mode.
  bindings:
  - expression: shell
    caller_bindable: true
- role_id: working-directory
  description: Legacy controlled role working-directory.
  bindings:
  - expression: cwd
    caller_bindable: true
facets:
- facet_id: legacy-facet-893d9d9f
  capability: Spawn any executable binary reachable via the system PATH or an absolute path, passing attacker-controlled arguments.
  role_ids:
  - command
  - environment
  - executable
  - shell-mode
  - working-directory
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: environment
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
    - predicate: role-bound
      subject: working-directory
      operator: equals
      value: true
- facet_id: legacy-facet-a25af164
  capability: 'Execute arbitrary shell commands via `shell=True`, which invokes /bin/sh (POSIX) or cmd.exe (Windows) with the full power of shell syntax: command chaining (`;`, `&&`, `||`), pipes (`|`), redirections (`>`, `<`, `>>`), command substitution (`$(...)`, `` `...` ``), subshells (`(...)`), and environment variable expansion.'
  role_ids:
  - command
  - environment
  - executable
  - shell-mode
  - working-directory
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: environment
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
    - predicate: role-bound
      subject: working-directory
      operator: equals
      value: true
- facet_id: legacy-facet-010f5f77
  capability: Run any script interpreter (python, perl, ruby, node, php, lua, etc.) with attacker-supplied code via `-c` / `-e` flags or inline via heredoc/pipe.
  role_ids:
  - command
  - environment
  - executable
  - shell-mode
  - working-directory
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: environment
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
    - predicate: role-bound
      subject: working-directory
      operator: equals
      value: true
- facet_id: legacy-facet-ae0dc478
  capability: 'Exploit GTFOBins "shell escape" binaries — programs not normally considered shells but that offer code/command execution primitives: `find -exec`, `tar --checkpoint=1 --checkpoint-action=exec=...`, `git -c core.gitProxy=...`, `awk ''BEGIN{system("...")}''`, `xargs sh -c`, `make -f /dev/stdin`, `vim -c '':!...''`, `man -P ''!...''`, `less ''!...''`, `ftp> !...`, `more`, `nmap --script`, `perl -e`, `ruby -e`, `ssh -o ProxyCommand=...`, and hundreds more.'
  role_ids:
  - command
  - environment
  - executable
  - shell-mode
  - working-directory
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: environment
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
    - predicate: role-bound
      subject: working-directory
      operator: equals
      value: true
- facet_id: legacy-facet-ed6b3388
  capability: Replace the actual executed binary via the `executable` parameter — the `args[0]` (program name seen by the child) differs from the binary the kernel loads. This enables spoofing the process listing while executing a different payload.
  role_ids:
  - command
  - environment
  - executable
  - shell-mode
  - working-directory
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: environment
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
    - predicate: role-bound
      subject: working-directory
      operator: equals
      value: true
- facet_id: legacy-facet-49a7b7bd
  capability: 'Set the child''s environment via `env`, injecting or overriding any variable: `PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, `PERL5LIB`, `RUBYLIB`, `HOME`, proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`), and application-specific configuration variables. A custom `env` dict REPLACES the parent''s environment entirely unless os.environ is explicitly merged.'
  role_ids:
  - command
  - environment
  - executable
  - shell-mode
  - working-directory
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: environment
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
    - predicate: role-bound
      subject: working-directory
      operator: equals
      value: true
- facet_id: legacy-facet-ed1dfca9
  capability: Run pre-execution hooks via `preexec_fn` — an arbitrary Python callable that executes in the child process after fork but before exec. This runs as the target user with full access to the child's address space, file descriptors, and OS state.
  role_ids:
  - command
  - environment
  - executable
  - shell-mode
  - working-directory
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: environment
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
    - predicate: role-bound
      subject: working-directory
      operator: equals
      value: true
- facet_id: legacy-facet-d62a6d40
  capability: Change the child's working directory to any accessible path via `cwd`, including sensitive/system directories (`/etc`, `/root`, `/proc`, `/sys`, `/tmp`, mount points).
  role_ids:
  - command
  - environment
  - executable
  - shell-mode
  - working-directory
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: environment
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
    - predicate: role-bound
      subject: working-directory
      operator: equals
      value: true
- facet_id: legacy-facet-4f91106b
  capability: Drop or assume OS-level user/group identity on POSIX via `user`, `group`, `extra_groups` — execute as root (if parent has CAP_SETUID), switch to another user, or join supplementary groups.
  role_ids:
  - command
  - environment
  - executable
  - shell-mode
  - working-directory
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: environment
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
    - predicate: role-bound
      subject: working-directory
      operator: equals
      value: true
- facet_id: legacy-facet-309b8801
  capability: Create a new process group or session via `process_group` and `start_new_session`, enabling daemonization and detachment from the controlling terminal.
  role_ids:
  - command
  - environment
  - executable
  - shell-mode
  - working-directory
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: environment
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
    - predicate: role-bound
      subject: working-directory
      operator: equals
      value: true
- facet_id: legacy-facet-fa324535
  capability: Set the child's file creation mask via `umask`, controlling permissions of any files the child creates.
  role_ids:
  - command
  - environment
  - executable
  - shell-mode
  - working-directory
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: environment
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
    - predicate: role-bound
      subject: working-directory
      operator: equals
      value: true
- facet_id: legacy-facet-4ba411b5
  capability: 'Control which file descriptors the child inherits: `close_fds=True` closes all non-essential FDs; `pass_fds` whitelists specific FDs to keep open (enabling stealthy FD-based IPC or leaking open sockets).'
  role_ids:
  - command
  - environment
  - executable
  - shell-mode
  - working-directory
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: environment
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
    - predicate: role-bound
      subject: working-directory
      operator: equals
      value: true
- facet_id: legacy-facet-97cab300
  capability: Establish bidirectional IPC with the child via `stdin=PIPE`, `stdout=PIPE`, `stderr=PIPE`, allowing the attacker to send input to and read output from the spawned process programmatically.
  role_ids:
  - command
  - environment
  - executable
  - shell-mode
  - working-directory
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: environment
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
    - predicate: role-bound
      subject: working-directory
      operator: equals
      value: true
- facet_id: legacy-facet-bca94e6d
  capability: Redirect child stdio to arbitrary file handles or open file objects, including `/dev/null`, network sockets, or existing log files (for stealth or data exfiltration).
  role_ids:
  - command
  - environment
  - executable
  - shell-mode
  - working-directory
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: environment
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
    - predicate: role-bound
      subject: working-directory
      operator: equals
      value: true
- facet_id: legacy-facet-70b0827d
  capability: Provide the full argument vector as a list (safe tokenization) or as a single string (when `shell=True` or on Windows with `.bat`/`.cmd` files, the string is parsed by the shell, enabling injection through unescaped metacharacters).
  role_ids:
  - command
  - environment
  - executable
  - shell-mode
  - working-directory
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: environment
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
    - predicate: role-bound
      subject: working-directory
      operator: equals
      value: true
- facet_id: legacy-facet-2c6451ce
  capability: 'On Windows: control process window appearance and priority via `startupinfo` and `creationflags`; `.bat`/`.cmd` files are always launched through cmd.exe regardless of `shell=False`.'
  role_ids:
  - command
  - environment
  - executable
  - shell-mode
  - working-directory
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: environment
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
    - predicate: role-bound
      subject: working-directory
      operator: equals
      value: true
- facet_id: legacy-facet-cabb7941
  capability: The `args` parameter accepts a sequence of program arguments — the first element is the program name (resolved via PATH) and the rest are its arguments, each fully attacker-controllable.
  role_ids:
  - command
  - environment
  - executable
  - shell-mode
  - working-directory
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: environment
      operator: equals
      value: true
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
    - predicate: role-bound
      subject: shell-mode
      operator: equals
      value: true
    - predicate: role-bound
      subject: working-directory
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-35997496
  role_id: null
  value: '`shell=False` by default — no implicit shell parsing; the command is executed directly via exec.'
  security_effect: '`shell=False` by default — no implicit shell parsing; the command is executed directly via exec.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-d7286d00
  role_id: null
  value: '`close_fds=True` by default on POSIX — file descriptors are not inherited unless explicitly passed via `pass_fds`.'
  security_effect: '`close_fds=True` by default on POSIX — file descriptors are not inherited unless explicitly passed via `pass_fds`.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-1fa0adf3
  role_id: null
  value: '`env=None` by default — the child inherits the parent''s full environment (HOME, PATH, proxy settings, cloud metadata endpoints, CI tokens, etc.).'
  security_effect: '`env=None` by default — the child inherits the parent''s full environment (HOME, PATH, proxy settings, cloud metadata endpoints, CI tokens, etc.).'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-071938cb
  role_id: null
  value: '`cwd=None` by default — the child''s working directory is the parent''s cwd, which may be a sensitive directory.'
  security_effect: '`cwd=None` by default — the child''s working directory is the parent''s cwd, which may be a sensitive directory.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-2bac13e7
  role_id: null
  value: '`executable=None` by default — the program to execute is the first element of `args`; no substitution occurs unless explicitly set.'
  security_effect: '`executable=None` by default — the program to execute is the first element of `args`; no substitution occurs unless explicitly set.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-3b70f1a0
  role_id: null
  value: '`stdin=None`, `stdout=None`, `stderr=None` by default — the child''s stdio is connected to the parent''s terminal/console (no capture, no pipe).'
  security_effect: '`stdin=None`, `stdout=None`, `stderr=None` by default — the child''s stdio is connected to the parent''s terminal/console (no capture, no pipe).'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-20582afe
  role_id: null
  value: The spawned process inherits the parent's umask, signal handlers (unless `restore_signals=True`), and resource limits.
  security_effect: The spawned process inherits the parent's umask, signal handlers (unless `restore_signals=True`), and resource limits.
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
