# fetch and OpenClaw web-fetch boundary

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-6dd212df5e76a743
api: fetch and OpenClaw web-fetch boundary
api_family: javascript.fetch
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: javascript
  version: legacy-source-bound
capability_class: network-egress
normative_authority: capability-facts-only
bound_sinks:
- fetch
- runWebFetch
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: url
    caller_bindable: true
facets:
- facet_id: legacy-facet-25053ff9
  capability: Send an outbound request to a caller-selected URL with caller-influenced method, headers, and body and return the response content available to the agent.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-02bf4397
  role_id: null
  value: DNS resolution, redirects, proxy settings, URL parsing, credentials policy, and ambient network reachability affect the reachable target set and information that can leave the process.
  security_effect: DNS resolution, redirects, proxy settings, URL parsing, credentials policy, and ambient network reachability affect the reachable target set and information that can leave the process.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: await fetch("https://example.com/status")
  capability_edge: await fetch(selectedUrl, selectedRequestInit)
provenance:
- https://developer.mozilla.org/docs/Web/API/fetch
```
