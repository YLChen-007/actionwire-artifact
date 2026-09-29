# CodeG.Transport.call:acp_prompt

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-8a9da68c64547d0e
api: CodeG.Transport.call:acp_prompt
api_family: codeg.external-agent-execution
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: codeg
  version: legacy-source-bound
capability_class: external-agent-execution
normative_authority: capability-facts-only
bound_sinks:
- getTransport.call:acp_prompt
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-b6b0f2db
  capability: Sends model/user prompt blocks across CodeG's TypeScript transport boundary to the Rust ACP connection manager, where the selected external coding-agent runtime owns its tool execution.
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-a4c4f054
  role_id: null
  value: The connection id selects one of CodeG's registered agent runtimes. This TypeScript model stops at the Rust ACP boundary and does not claim recovery of tools implemented by the external agent or by CodeG's Rust codeg-mcp companion.
  security_effect: The connection id selects one of CodeG's registered agent runtimes. This TypeScript model stops at the Rust ACP boundary and does not claim recovery of tools implemented by the external agent or by CodeG's Rust codeg-mcp companion.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'getTransport().call("acp_prompt", { connectionId, blocks: reviewedBlocks })'
  capability_edge: 'getTransport().call("acp_prompt", { connectionId, blocks: untrustedPromptBlocks })'
provenance:
- benchmark/typescript/codeg/src/lib/api.ts
```
