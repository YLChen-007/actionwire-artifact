# InteractiveShell.run_cell

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-3498f72e17a9cb50
api: InteractiveShell.run_cell
api_family: IPython.run_cell
runtime:
  language: python
  ecosystem: python-runtime
  package: IPython
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
- facet_id: legacy-facet-843b8aa5
  capability: Execute arbitrary Python source code in the IPython kernel process (the code
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-873af271
  capability: Invoke `__import__` (equivalently `import`) to load ANY module installed in
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-c14c9b52
  capability: 'Spawn child OS processes via multiple paths:'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-855cdcbf
  capability: Read, write, create, and delete arbitrary filesystem entries within the
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-ad13b74a
  capability: Change the kernel's working directory via `%cd <path>` (also `os.chdir`);
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-b9e4089f
  capability: 'Establish arbitrary network connections:'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-d2fa43a3
  capability: Install arbitrary Python packages at runtime via `%pip install <pkg>` or
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-f2df06a7
  capability: 'Read, write, and delete environment variables:'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-f7b4de18
  capability: 'Access and mutate the full interactive namespace (`user_ns`):'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-2dc94dcc
  capability: 'Access IPython input/output history:'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-e090ac4e
  capability: 'Define persistent IPython magics, aliases, and macros at runtime:'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-7a0dbf89
  capability: Register and execute custom transformers (input transformers run on every
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-6390c61c
  capability: Enable GUI event-loop integration via `%gui <backend>` (asyncio, qt, tk,
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-5253d854
  capability: 'Configure the IPython shell at runtime:'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-80ce1255
  capability: Invoke `ctypes.CDLL` / `ctypes.pythonapi` to call arbitrary C functions in
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-2a502dab
  capability: Access the underlying platform via `sys.platform`, `os.uname`, `platform`
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
- default_id: legacy-default-170acba3
  role_id: null
  value: Code runs IN-PROCESS in the IPython kernel — there is no subprocess
  security_effect: Code runs IN-PROCESS in the IPython kernel — there is no subprocess
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-67c93a0c
  role_id: null
  value: The interactive namespace (`user_ns`) is SHARED across all cells. Any
  security_effect: The interactive namespace (`user_ns`) is SHARED across all cells. Any
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-0e11c366
  role_id: null
  value: IPython's `automagic` is ON by default — `system` works as `%system`,
  security_effect: IPython's `automagic` is ON by default — `system` works as `%system`,
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-5628d33d
  role_id: null
  value: 'Auto-display: the return value of the last expression in a cell is'
  security_effect: 'Auto-display: the return value of the last expression in a cell is'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-dc4993c1
  role_id: null
  value: Rich tracebacks are ON by default — exception tracebacks include absolute
  security_effect: Rich tracebacks are ON by default — exception tracebacks include absolute
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-5eb4e9ce
  role_id: null
  value: '`!command` in a cell auto-escapes to the system shell (`/bin/sh` on'
  security_effect: '`!command` in a cell auto-escapes to the system shell (`/bin/sh` on'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-d263c870
  role_id: null
  value: '`!!command` captures stdout as a list of lines and returns it as a Python'
  security_effect: '`!!command` captures stdout as a list of lines and returns it as a Python'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-bafb5fd5
  role_id: null
  value: The kernel typically runs with the same environment, PATH, and credentials
  security_effect: The kernel typically runs with the same environment, PATH, and credentials
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-e1aeb6c4
  role_id: null
  value: '`%run` executes the target file with `__name__ == "__main__"`, so any'
  security_effect: '`%run` executes the target file with `__name__ == "__main__"`, so any'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-bc8e7bce
  role_id: null
  value: Import hooks and `sys.path` modifications persist across cells — a cell
  security_effect: Import hooks and `sys.path` modifications persist across cells — a cell
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
