# Chrome MCP client.callTool

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-d358ceb8a69bab68
api: Chrome MCP client.callTool
api_family: openclaw.chrome-mcp-rpc
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: openclaw
  version: legacy-source-bound
capability_class: rpc-boundary
normative_authority: capability-facts-only
bound_sinks:
- Chrome MCP client.callTool
roles:
- role_id: payload
  description: Legacy controlled role payload.
  bindings:
  - expression: payload
    caller_bindable: true
facets:
- facet_id: legacy-facet-11d39c02
  capability: Delegate a browser action to the Chrome MCP receiver, including evaluation when the literal tool name is evaluate_script and caller-influenced function text is present in the arguments payload.
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
- default_id: legacy-default-5af00398
  role_id: null
  value: Session attachment, receiver-side tool registration, browser profile policy, and receiver-side validation constrain the final browser effect; the sender-side call does not prove those checks.
  security_effect: Session attachment, receiver-side tool registration, browser profile policy, and receiver-side validation constrain the final browser effect; the sender-side call does not prove those checks.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'client.callTool({ name: "list_pages", arguments: {} })'
  capability_edge: 'client.callTool({ name: "evaluate_script", arguments: { function: source } })'
provenance:
- extensions/browser/src/browser/chrome-mcp.ts
```
