# Mattermost._api_post('posts', payload)

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-42ddc244112904fc
api: Mattermost._api_post('posts', payload)
api_family: mattermost._api_post.posts
runtime:
  language: python
  ecosystem: python-runtime
  package: mattermost
  version: legacy-source-bound
capability_class: delivery-render
normative_authority: capability-facts-only
bound_sinks:
- adapter._api_post('posts', payload)
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: message
    caller_bindable: true
  - expression: payload
    caller_bindable: true
facets:
- facet_id: legacy-facet-8ec9e13e
  capability: Create a Mattermost post using the configured integration identity.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-1631d2ef
  role_id: null
  value: Mattermost markdown and mention parsing apply to the message field.
  security_effect: Mattermost markdown and mention parsing apply to the message field.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'await adapter._api_post(''posts'', {''channel_id'': channel, ''message'': ''hello''})'
  capability_edge: Unfiltered @all or @channel content can notify a broad audience.
provenance:
- src/ql/call/sinks_af.qll Mattermost posts sink
```
