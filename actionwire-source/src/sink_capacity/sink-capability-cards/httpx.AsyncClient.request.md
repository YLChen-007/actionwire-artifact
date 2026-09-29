# httpx.AsyncClient.request(method, url, *, content=..., data=..., files=..., json=..., params=..., headers=..., ...)

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-e352d2bb8467e0f3
api: httpx.AsyncClient.request(method, url, *, content=..., data=..., files=..., json=..., params=..., headers=..., ...)
api_family: httpx.AsyncClient.request
runtime:
  language: python
  ecosystem: python-runtime
  package: httpx
  version: legacy-source-bound
capability_class: network-egress
normative_authority: capability-facts-only
bound_sinks: []
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: url
    caller_bindable: true
- role_id: headers
  description: Legacy controlled role headers.
  bindings:
  - expression: headers
    caller_bindable: true
- role_id: request-body
  description: Legacy controlled role request-body.
  bindings:
  - expression: data
    caller_bindable: true
- role_id: statement
  description: Legacy controlled role statement.
  bindings:
  - expression: query
    caller_bindable: true
facets:
- facet_id: legacy-facet-dfc6be08
  capability: 'Calling this API can connect to a network destination, transmit request metadata or body data, and receive a response. `AsyncClient.request` is method-generic: the caller, rather than the API name, determines whether the operation is a read, create, update, or delete.'
  role_ids:
  - destination-url
  - headers
  - request-body
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
    - predicate: role-bound
      subject: headers
      operator: equals
      value: true
    - predicate: role-bound
      subject: request-body
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
library_guarantees: []
defaults: []
example_usage:
  benign: See the source-owned legacy card for the original benign example.
  capability_edge: See the source-owned legacy card for the original capability-edge example.
provenance:
- source-owned legacy capability card
```
