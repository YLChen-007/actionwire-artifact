# Response.text

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-2f1e57a5914a6eae
api: Response.text
api_family: javascript.response-text
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: javascript
  version: legacy-source-bound
capability_class: resource-consumption
normative_authority: capability-facts-only
bound_sinks:
- Response.text
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: url
    caller_bindable: true
facets:
- facet_id: legacy-facet-3074db0b
  capability: Consume an HTTP response body into a complete in-memory string. When the selected remote endpoint controls the response and no byte limit is enforced before this call, body size can drive memory and CPU consumption.
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
- default_id: legacy-default-5328897f
  role_id: null
  value: The Fetch implementation's decompression, streaming, redirect, and allocation behavior determines the final resource cost; truncating the resulting string after text() returns does not bound the preceding body read.
  security_effect: The Fetch implementation's decompression, streaming, redirect, and allocation behavior determines the final resource cost; truncating the resulting string after text() returns does not bound the preceding body read.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: await response.text() after enforcing a small streamed byte limit
  capability_edge: await attackerSelectedResponse.text()
provenance:
- https://developer.mozilla.org/docs/Web/API/Response/text
```
