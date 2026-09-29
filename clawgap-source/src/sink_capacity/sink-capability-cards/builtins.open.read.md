# builtins.open

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-7ad97738afe62a6b
api: builtins.open
api_family: builtins.open.read
runtime:
  language: python
  ecosystem: python-runtime
  package: builtins
  version: legacy-source-bound
capability_class: file-read
normative_authority: capability-facts-only
bound_sinks:
- open(path, 'r')
- open(path, 'rb')
- open(path, 'rt')
- open(path)
roles:
- role_id: path
  description: Legacy controlled role path.
  bindings:
  - expression: file
    caller_bindable: true
facets:
- facet_id: legacy-facet-2b162a2c
  capability: Read the entire contents of any file on the local filesystem that the
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-857d6c2e
  capability: Read arbitrary files via absolute paths (e.g. /etc/passwd,
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-549e2b2c
  capability: Read arbitrary files via relative paths resolved against the processʼs
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-fa6f36cf
  capability: 'Read special filesystem objects whose contents expose runtime state:'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-885197da
  capability: Read device nodes (e.g. /dev/sda, /dev/tty) when permissions allow,
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-697b8e56
  capability: Read named pipes (FIFOs) and UNIX-domain socket files as regular
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-386b4d23
  capability: By default, open() follows symbolic links transparently — the caller
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-3fdf2397
  capability: If a file descriptor integer is passed as the `file` argument, the
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-a2f7f599
  capability: In text mode, the `encoding` keyword can be set to any codec known to
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-5f4044d3
  capability: With `errors='surrogateescape'` or similar, the attacker can read
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-d9f91270
  capability: The `newline` parameter in text mode controls universal-newline
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-bec4cee8
  capability: open() interacts with OS-level mandatory locking (if enabled on the
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
- default_id: legacy-default-827661bb
  role_id: null
  value: Default mode is 'rt' (read text) — calling open(path) without a mode
  security_effect: Default mode is 'rt' (read text) — calling open(path) without a mode
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-7554ddd7
  role_id: null
  value: Default encoding in text mode is locale.getencoding() (platform-
  security_effect: Default encoding in text mode is locale.getencoding() (platform-
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-7cf90e18
  role_id: null
  value: Relative paths resolve against os.getcwd(), which is the processʼs
  security_effect: Relative paths resolve against os.getcwd(), which is the processʼs
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-40b2cfeb
  role_id: null
  value: Symlink-following is the OS default and cannot be disabled through
  security_effect: Symlink-following is the OS default and cannot be disabled through
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-4ef5a83c
  role_id: null
  value: open() raises OSError on failure, but the error message includes the
  security_effect: open() raises OSError on failure, but the error message includes the
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: "# Normal usage: read a known data file\nwith open('data/input.txt', 'r') as f:\n    content = f.read()\nprint(content)"
  capability_edge: "# Attacker controls `path`: read /etc/passwd\npath = '../../../etc/passwd'\nwith open(path, 'r') as f:\n    print(f.read())\n\n# Read binary secrets (SSH private key)\npath = '/home/user/.ssh/id_rsa'\nwith open(path, 'rb') as f:\n    print(f.read())\n\n# Read /proc environ to leak env vars (including API keys)\nwith open('/proc/self/environ', 'r') as f:\n    for entry in f.read().split('\\0'):\n        print(entry)\n\n# Use fd wrapping to read an inherited file descriptor\nwith open(3, 'r') as f:\n    print(f.read())"
provenance:
- https://docs.python.org/3/library/functions.html#open
- POSIX open(2) symlink resolution
- CWE-22 Path Traversal
```
