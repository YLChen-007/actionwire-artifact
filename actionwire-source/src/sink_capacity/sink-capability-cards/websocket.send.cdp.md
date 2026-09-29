# WebSocket.send (Chrome DevTools Protocol dispatch)

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-b1be3d770f069466
api: WebSocket.send (Chrome DevTools Protocol dispatch)
api_family: websocket.send.cdp
runtime:
  language: python
  ecosystem: python-runtime
  package: websocket
  version: legacy-source-bound
capability_class: code-eval
normative_authority: capability-facts-only
bound_sinks:
- ws.send(json.dumps(cdp_request))
roles:
- role_id: query-parameters
  description: Legacy controlled role query-parameters.
  bindings:
  - expression: params
    caller_bindable: true
facets:
- facet_id: legacy-facet-76d097db
  capability: Dispatch browser-debugger operations, including Runtime.evaluate, against the connected target.
  role_ids:
  - query-parameters
  activation:
    any_of:
    - predicate: role-bound
      subject: query-parameters
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-5ffacda8
  role_id: null
  value: The active browser session, its credentials, origin state, and network reachability are inherited.
  security_effect: The active browser session, its credentials, origin state, and network reachability are inherited.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'await ws.send(json.dumps({''method'': ''Runtime.evaluate'', ''params'': {''expression'': ''document.title''}}))'
  capability_edge: A controlled Runtime.evaluate expression can execute JavaScript and read or transmit page state.
provenance:
- src/ql/call/sinks_af.qll WebSocket CDP sink
```
