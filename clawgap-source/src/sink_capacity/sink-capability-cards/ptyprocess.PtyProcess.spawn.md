# ptyprocess.PtyProcess.spawn

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-eaa5dd3446cb5458
api: ptyprocess.PtyProcess.spawn
api_family: ptyprocess.PtyProcess.spawn
runtime:
  language: python
  ecosystem: python-runtime
  package: ptyprocess
  version: legacy-source-bound
capability_class: process-spawn
normative_authority: capability-facts-only
bound_sinks:
- PtyProcess.spawn(argv, ...)
roles:
- role_id: executable
  description: Legacy controlled role executable.
  bindings:
  - expression: executable
    caller_bindable: true
facets:
- facet_id: legacy-facet-83faf570
  capability: Start an operating-system process attached to a pseudo-terminal.
  role_ids:
  - executable
  activation:
    any_of:
    - predicate: role-bound
      subject: executable
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-43fd12e6
  role_id: null
  value: The child inherits ambient user privileges and any environment or working-directory values supplied by the caller.
  security_effect: The child inherits ambient user privileges and any environment or working-directory values supplied by the caller.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: PtyProcess.spawn(['/bin/sh', '-lc', 'echo hello'])
  capability_edge: A controlled argv can execute arbitrary commands with the agent process privileges.
provenance:
- src/ql/call/sinks_af.qll PTY spawn sink
```
