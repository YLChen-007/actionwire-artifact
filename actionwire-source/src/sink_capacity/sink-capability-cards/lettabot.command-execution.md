# LettaCode.Bash

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-d2369174fc750f71
api: LettaCode.Bash
api_family: lettabot.command-execution
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: lettabot
  version: legacy-source-bound
capability_class: command-execution
normative_authority: capability-facts-only
bound_sinks:
- Bash
roles:
- role_id: command
  description: Legacy controlled role command.
  bindings:
  - expression: command
    caller_bindable: true
facets:
- facet_id: legacy-facet-bee654fa
  capability: Execute a model-selected shell command in the Letta Code working directory, either in the foreground or as a tracked background process.
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
- default_id: legacy-default-3723a326
  role_id: null
  value: Foreground execution defaults to a 120 second timeout; the implementation selects a platform shell launcher and caps the timeout at 600 seconds.
  security_effect: Foreground execution defaults to a 120 second timeout; the implementation selects a platform shell launcher and caps the timeout at 600 seconds.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'Bash({ command: "git status" })'
  capability_edge: 'Bash({ command: modelCommand, run_in_background: modelBackground })'
provenance:
- benchmark/typescript/lettabot/vendor-source/letta-code-v0.19.5/src/tools/impl/Bash.ts
```
