# outbound adapter registry sendMedia

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-dc08a8d04eefe90b
api: outbound adapter registry sendMedia
api_family: openclaw-cn.delivery
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: openclaw-cn
  version: legacy-source-bound
capability_class: delivery
normative_authority: capability-facts-only
bound_sinks:
- ChannelOutboundAdapter.sendMedia
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: url
    caller_bindable: true
facets:
- facet_id: legacy-facet-a8f84dc1
  capability: Delegate a model-selected outbound media payload to the configured channel adapter.
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
- default_id: legacy-default-cd53b2d3
  role_id: null
  value: The selected account, channel registry, adapter credentials, and delivery mode determine the external authority.
  security_effect: The selected account, channel registry, adapter credentials, and delivery mode determine the external authority.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: handler.sendMedia("report", "https://example.com/report.pdf")
  capability_edge: handler.sendMedia(selectedCaption, selectedMediaUrl)
provenance:
- benchmark/typescript/openclaw-cn/src/infra/outbound/deliver.ts
```
