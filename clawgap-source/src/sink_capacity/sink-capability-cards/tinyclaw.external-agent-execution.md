# node:child_process.spawn for a registered external agent CLI

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-08844c9c6ba4951d
api: node:child_process.spawn for a registered external agent CLI
api_family: tinyclaw.external-agent-execution
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: tinyclaw
  version: legacy-source-bound
capability_class: external-agent-execution
normative_authority: capability-facts-only
bound_sinks:
- spawn:external-agent-cli
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: message
    caller_bindable: true
facets:
- facet_id: legacy-facet-35f4cb45
  capability: Starts a registered Claude, Codex, or OpenCode CLI adapter and gives that external agent the selected message, model, working directory, environment, and TinyClaw's configured bypass flags.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-b54a9667
  role_id: null
  value: The external CLI owns its internal tool graph; this core TypeScript model stops at the process boundary and does not claim recovery of tools implemented inside those external programs.
  security_effect: The external CLI owns its internal tool graph; this core TypeScript model stops at the process boundary and does not claim recovery of tools implemented inside those external programs.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'spawn("codex", ["exec", "--json", reviewedMessage], { cwd: workspace })'
  capability_edge: spawn(selectedAgentCli, argvContainingModelMessage, { cwd, env })
provenance:
- benchmark/typescript/tinyclaw/packages/core/src/invoke.ts
```
