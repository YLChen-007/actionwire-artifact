# builtins.open (write/append/create modes: 'w', 'a', 'x', and their

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-9cf089928a270084
api: 'builtins.open (write/append/create modes: ''w'', ''a'', ''x'', and their'
api_family: builtins.open.write
runtime:
  language: python
  ecosystem: python-runtime
  package: builtins
  version: legacy-source-bound
capability_class: file-write
normative_authority: capability-facts-only
bound_sinks: []
roles:
- role_id: path
  description: Legacy controlled role path.
  bindings:
  - expression: file
    caller_bindable: true
  - expression: path
    caller_bindable: true
facets:
- facet_id: legacy-facet-44791478
  capability: Write arbitrary content to any path the process uid can create/write.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-0a55adf3
  capability: Truncate (overwrite) any existing writable file when mode contains 'w'.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-cc25a621
  capability: Append to any existing writable file when mode contains 'a' (creates the
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-6de00b4f
  capability: Exclusive-create a new file when mode contains 'x' (raises FileExistsError
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-832d62f6
  capability: Write arbitrary raw bytes in binary mode ('b') — no encoding/decoding,
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-e3478118
  capability: Write text with a chosen encoding in text mode ('t', the default) —
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-8084ec8a
  capability: Path-traversal via '../' sequences in `file` to escape any intended
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-7d5208b4
  capability: Absolute paths in `file` bypass any directory sandboxing entirely
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-a7c117fa
  capability: 'Overwrite security-critical files: ~/.ssh/authorized_keys (SSH access'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-3b9e96d8
  capability: Write into /proc/self/ or /proc/<pid>/ (e.g., /proc/self/mem for memory
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-2ec45519
  capability: Write into /dev/ devices (e.g., /dev/tty to write to the controlling
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-e252246f
  capability: Overwrite the program's own source files, configuration, or plugin
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-38b0b933
  capability: Write dotfiles in the home directory to establish long-term persistence.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-4815cf55
  capability: Create files with arbitrary names including hidden files (leading dot),
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-8bda8bd9
  capability: Read-and-write modes ('w+', 'a+') allow writing AND then reading back
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-828b5090
  capability: The `opener` parameter allows passing a custom callable that returns a
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-a8726573
  capability: The file parameter accepts an integer file descriptor — if the attacker
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
- default_id: legacy-default-d7b16119
  role_id: null
  value: Default mode is 'rt' (read-text), but once the attacker controls `mode`
  security_effect: Default mode is 'rt' (read-text), but once the attacker controls `mode`
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-24deb032
  role_id: null
  value: Default encoding in text mode is locale-dependent
  security_effect: Default encoding in text mode is locale-dependent
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-3e04a47b
  role_id: null
  value: Default newline translation in text mode converts '\n' to the
  security_effect: Default newline translation in text mode converts '\n' to the
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-034d43da
  role_id: null
  value: 'Default buffering: text-mode files connected to a tty use line'
  security_effect: 'Default buffering: text-mode files connected to a tty use line'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-ec610ca6
  role_id: null
  value: By default, `file` paths are resolved relative to the process's current
  security_effect: By default, `file` paths are resolved relative to the process's current
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-a5762044
  role_id: null
  value: Symlinks are followed by default — writing to a path that is a symlink
  security_effect: Symlinks are followed by default — writing to a path that is a symlink
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-52919cce
  role_id: null
  value: The process's umask, uid, gid, and supplemental groups govern
  security_effect: The process's umask, uid, gid, and supplemental groups govern
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-6fd12fd1
  role_id: null
  value: '`closefd=True` by default — when wrapping an integer file descriptor,'
  security_effect: '`closefd=True` by default — when wrapping an integer file descriptor,'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-5b71d02c
  role_id: null
  value: 'No parent-directory creation: open() does NOT create missing parent'
  security_effect: 'No parent-directory creation: open() does NOT create missing parent'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-85c5b905
  role_id: null
  value: open() raises auditing event 'open' with arguments (file, mode, flags)
  security_effect: open() raises auditing event 'open' with arguments (file, mode, flags)
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
