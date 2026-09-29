# Exa.get_contents

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-a309a17d912d3b7f
api: Exa.get_contents
api_family: exa.get_contents
runtime:
  language: python
  ecosystem: python-runtime
  package: exa
  version: legacy-source-bound
capability_class: network-egress
normative_authority: capability-facts-only
bound_sinks:
- exa_client.get_contents(ids_or_urls, ...)
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: urls
    caller_bindable: true
facets:
- facet_id: legacy-facet-275c4414
  capability: Ask the Exa service to retrieve content selected by the caller.
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
- default_id: legacy-default-66dfe2a2
  role_id: null
  value: The configured Exa credential, service-side fetch policy, and response limits apply.
  security_effect: The configured Exa credential, service-side fetch policy, and response limits apply.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: client.get_contents(['https://example.com'])
  capability_edge: Unrestricted caller-selected targets can retrieve and return unintended remote content.
provenance:
- src/ql/call/sinks_af.qll Exa sink
```
