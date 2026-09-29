# callGatewayTool(method)

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-050edbb6c95d6153
api: callGatewayTool(method)
api_family: openclaw.gateway-rpc
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: openclaw
  version: legacy-source-bound
capability_class: rpc-boundary
normative_authority: capability-facts-only
bound_sinks:
- callGatewayTool:config.*
- callGatewayTool:cron.*
- callGatewayTool:update.run
- callGatewayTool:wake
roles:
- role_id: payload
  description: Legacy controlled role payload.
  bindings:
  - expression: payload
    caller_bindable: true
facets:
- facet_id: legacy-facet-e881c166
  capability: Invoke a fixed capability-bearing gateway method with a method-specific caller-influenced payload, including configuration mutation, update, cron scheduling/execution, and wake operations.
  role_ids:
  - payload
  activation:
    any_of:
    - predicate: role-bound
      subject: payload
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-255cbf16
  role_id: null
  value: Gateway authentication, method-scope authorization, server configuration, and the remote implementation bound the delegated effect; the sender-side boundary does not prove receiver-side checks.
  security_effect: Gateway authentication, method-scope authorization, server configuration, and the remote implementation bound the delegated effect; the sender-side boundary does not prove receiver-side checks.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'callGatewayTool("cron.list", gatewayOpts, { includeDisabled: false })'
  capability_edge: callGatewayTool(literalCapabilityMethod, gatewayOpts, selectedMethodPayload)
provenance:
- benchmark/typescript/openclaw/src/agents/tools/gateway-tool.ts
- benchmark/typescript/openclaw/src/agents/tools/cron-tool.ts
```
