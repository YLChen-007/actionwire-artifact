# callGatewayTool(node.invoke)

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-c336b256331928de
api: callGatewayTool(node.invoke)
api_family: openclaw.node-invoke
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: openclaw
  version: legacy-source-bound
capability_class: rpc-node-invoke
normative_authority: capability-facts-only
bound_sinks:
- callGatewayTool:node.invoke
roles:
- role_id: command
  description: Legacy controlled role command.
  bindings:
  - expression: command
    caller_bindable: true
facets:
- facet_id: legacy-facet-4eab614d
  capability: Invoke an explicitly named capability on a selected paired node with caller-influenced parameters, including local process execution when the literal command is system.run.
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
- default_id: legacy-default-a76d2fbc
  role_id: null
  value: Pairing state, node identity resolution, the receiver command allowlist, approval policy, environment, and the paired node's local privileges bound the delegated capability.
  security_effect: Pairing state, node identity resolution, the receiver command allowlist, approval policy, environment, and the paired node's local privileges bound the delegated capability.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'callGatewayTool("node.invoke", gatewayOpts, { nodeId, command: "system.notify", params: notice })'
  capability_edge: 'callGatewayTool("node.invoke", gatewayOpts, { nodeId: selectedNode, command: "system.run", params: selectedRunParams })'
provenance:
- benchmark/typescript/openclaw/src/agents/tools/nodes-tool.ts
```
