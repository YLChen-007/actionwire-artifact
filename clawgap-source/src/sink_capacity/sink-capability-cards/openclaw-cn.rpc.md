# node.invoke browser.proxy and system.run

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-b0974c719276e1d7
api: node.invoke browser.proxy and system.run
api_family: openclaw-cn.rpc
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: openclaw-cn
  version: legacy-source-bound
capability_class: rpc-boundary
normative_authority: capability-facts-only
bound_sinks:
- node.invoke/browser.proxy
- node.invoke/system.run
roles:
- role_id: command
  description: Legacy controlled role command.
  bindings:
  - expression: command
    caller_bindable: true
- role_id: payload
  description: Legacy controlled role payload.
  bindings:
  - expression: payload
    caller_bindable: true
facets:
- facet_id: legacy-facet-a3149d39
  capability: Forward a model-selected browser or process operation to a paired node using a literal capability action.
  role_ids:
  - command
  - payload
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: payload
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-2c530291
  role_id: null
  value: Pairing, node identity, receiver-side authorization, decoding, and local runtime policy bound the delegated effect.
  security_effect: Pairing, node identity, receiver-side authorization, decoding, and local runtime policy bound the delegated effect.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'callGatewayTool("node.invoke", opts, { command: "browser.proxy", params })'
  capability_edge: callGatewayTool("node.invoke", opts, selectedCapabilityPayload)
provenance:
- benchmark/typescript/openclaw-cn/src/agents/tools/browser-tool.ts
- benchmark/typescript/openclaw-cn/src/node-host/runner.ts
```
