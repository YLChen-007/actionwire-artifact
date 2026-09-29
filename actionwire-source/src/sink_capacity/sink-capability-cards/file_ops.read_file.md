# ShellFileOperations.read_file

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-c028ec22c360c990
api: ShellFileOperations.read_file
api_family: file_ops.read_file
runtime:
  language: python
  ecosystem: project-source
  package: file_ops
  version: legacy-source-bound
capability_class: file-read
normative_authority: capability-facts-only
bound_sinks:
- ShellFileOperations.read_file_raw
roles:
- role_id: path
  description: Legacy controlled role path.
  bindings:
  - expression: file
    caller_bindable: true
  - expression: path
    caller_bindable: true
facets:
- facet_id: legacy-facet-4d959d44
  capability: Read any file on the filesystem accessible to the agent process (the process
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-7a40f5d8
  capability: 'The API delegates to POSIX shell utilities: `wc -c` (stat/probe), `head -c`'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-7b3ff628
  capability: Symlinks are transparently followed by the kernel `open(2)` call inside
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-334599c0
  capability: Relative paths (`./`, `../`, `../../etc/passwd`) are resolved against the
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-c7f81340
  capability: '`~` tilde expansion is performed via `echo $HOME` (or `echo ~username`)'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-b49451a2
  capability: Directory traversal (`../`) is not intercepted; every `../` segment is
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-bc1665e1
  capability: '`/proc/self/fd/N`, `/dev/stdin`, `/dev/fd/N` — file descriptors exposed'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-285943d2
  capability: Named pipes (FIFOs) and device nodes in `/dev/` are openable — `sed`/`cat`
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-4c3534cc
  capability: '`/proc/self/maps`, `/proc/self/environ`, `/proc/self/cmdline`, and other'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-d5ace3ac
  capability: '`/proc/self/cwd` (symlink to the current working directory) and'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-a8f3398b
  capability: 'File-existence oracle: `wc -c < path` returns exit code 0 for existing'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-25a59dd6
  capability: 'File-size oracle: even if content is not returned (binary detection'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-350915dd
  capability: 'Binary-detection bypass: the binary check examines only the first 1000'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-3493343f
  capability: '`read_file_raw` (the companion `bound_sink`) reads the entire file into'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-0279855b
  capability: The `_expand_path` → `_escape_shell_arg` pipeline resolves `~`, then wraps
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-efd4ce6b
  capability: The delegated utilities (`wc`, `head`, `sed`, `cat`) all follow the
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
- default_id: legacy-default-1f103852
  role_id: null
  value: Symlink following is the kernel default (`open(2)` without `O_NOFOLLOW`);
  security_effect: Symlink following is the kernel default (`open(2)` without `O_NOFOLLOW`);
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-855da74c
  role_id: null
  value: Relative paths resolve against the terminal environment's live `cwd`, not
  security_effect: Relative paths resolve against the terminal environment's live `cwd`, not
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-63e1f857
  role_id: null
  value: '`~` expands to `$HOME` of the uid running the agent process, which in'
  security_effect: '`~` expands to `$HOME` of the uid running the agent process, which in'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-98ecf688
  role_id: null
  value: Binary detection uses a 30%-non-printable threshold on the first 1000
  security_effect: Binary detection uses a 30%-non-printable threshold on the first 1000
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-0b5b776f
  role_id: null
  value: '`wc -c < path` reveals file existence regardless of content type (no'
  security_effect: '`wc -c < path` reveals file existence regardless of content type (no'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-1297d36c
  role_id: null
  value: Read errors and `FileNotFoundError` responses include directory listings
  security_effect: Read errors and `FileNotFoundError` responses include directory listings
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-52f80ca8
  role_id: null
  value: '`read_file_raw` uses `cat` with no line-count or size guard — the entire'
  security_effect: '`read_file_raw` uses `cat` with no line-count or size guard — the entire'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: '# Read the first 50 lines of a project config file

    result = file_ops.read_file("config/settings.yaml", offset=1, limit=50)

    print(result.content)'
  capability_edge: "# (1) Read /etc/shadow via direct absolute path\nresult = file_ops.read_file(\"/etc/shadow\", offset=1, limit=500)\n\n# (2) Read /proc/self/environ to extract API keys from agent's env\nresult = file_ops.read_file_raw(\"/proc/self/environ\")\n\n# (3) Symlink attack — if /tmp/link -> /root/.ssh/id_rsa exists\nresult = file_ops.read_file(\"/tmp/link\")\n\n# (4) Directory traversal from home\nresult = file_ops.read_file(\"~/../../../etc/passwd\")\n\n# (5) Read process cmdline to discover command-line secrets\nresult = file_ops.read_file(\"/proc/1/cmdline\")\n\n# (6) Binary-detection bypass — text header + binary payload\n# (file starts with 1000 bytes of printable text, then binary data)\nresult = file_ops.read_file(\"/var/lib/dpkg/status\")  # large text file\n\n# (7) Enumerate filesystem via error oracle\nfor candidate in [\"/root/.ssh/id_rsa\", \"/root/.aws/credentials\",\n                  \"/root/.config/gh/hosts.yml\"]:\n    r = file_ops.read_file(candidate)\n    if\
    \ r.error is None:\n        print(f\"FOUND: {candidate}\")"
provenance:
- 'tools/file_operations.py:1002-1097 — read_file implementation delegates to shell: wc -c (line 1020), head -c 1000 (line 1051), sed -n (line 1064), wc -l (line 1077)'
- tools/file_operations.py:1151-1188 — read_file_raw uses cat (line 1176) to read entire file; no pagination, no size cap
- tools/file_operations.py:853-888 — _expand_path resolves ~ via echo $HOME and ~username via shell expansion
- tools/file_operations.py:890-893 — _escape_shell_arg single-quote wraps the path for shell interpolation
- tools/file_operations.py:765-795 — _exec calls self.env.execute(command, cwd=...) delegating to terminal backend
- tools/environments/base.py:829-875 — BaseEnvironment.execute runs _run_bash which spawns bash subprocess
- tools/environments/local.py:549-604 — LocalEnvironment._run_bash uses subprocess.Popen([bash, '-c', cmd_string])
- POSIX open(2) symlink resolution — kernel follows symlinks by default; O_NOFOLLOW is never set
- CWE-22 Path Traversal — ../ sequences are resolved by the kernel in the child utility's open(2) call
```
