# pathlib.Path(...).open

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-f8fefdc32ae95fca
api: pathlib.Path(...).open
api_family: pathlib.Path.open
runtime:
  language: python
  ecosystem: python-runtime
  package: pathlib
  version: legacy-source-bound
capability_class: file-read
normative_authority: capability-facts-only
bound_sinks:
- Path(path).open('rb')
roles:
- role_id: path
  description: Legacy controlled role path.
  bindings:
  - expression: path
    caller_bindable: true
facets:
- facet_id: legacy-facet-4ab173e0
  capability: 'Read any file on the local filesystem via path traversal: `..` segments'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-b3448f76
  capability: 'Absolute-path injection: if any segment passed to Path() is an absolute'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-cfd735e7
  capability: 'Read special device files: `/dev/stdin` (reads from the processʼs own'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-02a911ce
  capability: 'Leak process internals via procfs (`/proc/self/` or `/proc/<pid>/`):'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-ec91b639
  capability: 'Leak kernel and hardware information via sysfs: `/sys/kernel/`,'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-81f4de0a
  capability: Binary mode (`'rb'`) bypasses encoding errors — any byte sequence is
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-861d4a9b
  capability: 'Read named pipes (FIFOs): opening a FIFO blocks until the other end'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-883af92f
  capability: 'Read symbolic links transparently: `open(2)` follows symlinks by'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-19df1daa
  capability: 'Read mount points and bind mounts: the filesystem namespace visible to'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-9678bc45
  capability: 'TOCTOU race: path resolution happens at `open(2)` call time, NOT at'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-c3d7d1c6
  capability: 'Write capability (mode `''w''`, `''a''`, `''w+''`, `''a+''`, `''x''`): if the'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-d2891626
  capability: 'Truncation via mode `''w''` or `''w+''`: existing file content is'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-a482d0a0
  capability: 'Read-write via mode `''r+''`: the file is opened for both reading and'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-300ffbb0
  role_id: null
  value: Symlink following is the default behavior — `open(2)` is called
  security_effect: Symlink following is the default behavior — `open(2)` is called
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-c36d5871
  role_id: null
  value: Relative paths are resolved against the processʼs current working
  security_effect: Relative paths are resolved against the processʼs current working
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-9d5087a8
  role_id: null
  value: Text-mode encoding defaults to `locale.getpreferredencoding(False)`,
  security_effect: Text-mode encoding defaults to `locale.getpreferredencoding(False)`,
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-f8904d85
  role_id: null
  value: The file is opened with the processʼs effective UID/GID and
  security_effect: The file is opened with the processʼs effective UID/GID and
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-ee6160c1
  role_id: null
  value: Buffering defaults to `-1` (system default, typically full buffering
  security_effect: Buffering defaults to `-1` (system default, typically full buffering
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-ac38c53d
  role_id: null
  value: No `Path.open()` parameter controls `O_CLOEXEC` — the file descriptor
  security_effect: No `Path.open()` parameter controls `O_CLOEXEC` — the file descriptor
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-51968164
  role_id: null
  value: Path construction via `/` operator inherits the same absolute-path-
  security_effect: Path construction via `/` operator inherits the same absolute-path-
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: "from pathlib import Path\n\n# Normal usage: open a known file in the project directory\nconfig = Path(\"config/settings.json\")\nwith config.open(\"r\") as f:\n    data = f.read()\nprint(f\"Config loaded: {data[:50]}...\")\n"
  capability_edge: "from pathlib import Path\n\n# ATTACKER-CONTROLLED: the path string comes from an untrusted source\nattacker_path = \"../../../etc/passwd\"\n\n# PATH TRAVERSAL — '..' is NOT collapsed by Path construction\np = Path(attacker_path)\nwith p.open(\"rb\") as f:\n    content = f.read()\nprint(f\"Read {len(content)} bytes from /etc/passwd\")\n\n# ---\n\n# ABSOLUTE PATH INJECTION — preceding segments are silently discarded\nbase = Path(\"/safe/data/dir\")\nevil = Path(base, \"/etc/shadow\")\n# evil resolves to PosixPath('/etc/shadow'), NOT /safe/data/dir/etc/shadow\nwith evil.open(\"rb\") as f:\n    shadow = f.read()\nprint(f\"Read {len(shadow)} bytes from /etc/shadow\")\n\n# ---\n\n# PROCFS — leak process environment (credentials in cleartext)\nwith Path(\"/proc/self/environ\").open(\"rb\") as f:\n    env_raw = f.read()\nfor line in env_raw.split(b\"\\x00\")[:3]:\n    print(line.decode(\"utf-8\", errors=\"replace\"))\n\n# ---\n\n# DEVICE FILE — read from the process's own stdin\n\
    with Path(\"/dev/stdin\").open(\"rb\") as f:\n    stdin_data = f.read(64)\nprint(f\"Stdin peek: {stdin_data}\")\n\n# ---\n\n# SYMLINK FOLLOWING — transparent, no way to disable\n# (ln -s /etc/hostname ./safe_link)\nwith Path(\"safe_link\").open(\"r\") as f:\n    hostname = f.read().strip()\nprint(f\"Hostname via symlink: {hostname}\")\n\n# ---\n\n# WRITE (if mode is also attacker-controlled)\nattacker_path_write = \"/tmp/attacker_planted.py\"\nwith Path(attacker_path_write).open(\"w\") as f:\n    f.write(\"print('arbitrary code written by attacker')\\n\")\nprint(f\"Wrote to {attacker_path_write}\")\n"
provenance:
- https://docs.python.org/3/library/pathlib.html#pathlib.Path.open
- POSIX open(2) symlink resolution
- CWE-22 Path Traversal
- CWE-59 Symlink Following (TOCTOU)
- CWE-73 External Control of File Name or Path
```
