# ChannelDeliveryAdapter.deliver:approval-card

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-becb9b3ff7721864
api: ChannelDeliveryAdapter.deliver:approval-card
api_family: nanoclaw.approval-presentation
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: nanoclaw
  version: legacy-source-bound
capability_class: approval-presentation
normative_authority: capability-facts-only
bound_sinks:
- adapter.deliver:approval-card
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: content
    caller_bindable: true
facets:
- facet_id: legacy-facet-458f990f
  capability: Present the facts on which a NanoClaw administrator makes an approval decision through the configured channel adapter.
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
- default_id: legacy-default-118beaae
  role_id: null
  value: Concrete channel implementations are outside the pinned core scope; the chat-sdk kind and ask_question payload identify this capability-explicit dependency-injection boundary.
  security_effect: Concrete channel implementations are outside the pinned core scope; the chat-sdk kind and ask_question payload identify this capability-explicit dependency-injection boundary.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: adapter.deliver(channel, platform, null, "chat-sdk", JSON.stringify(reviewedQuestion))
  capability_edge: adapter.deliver(channel, platform, null, "chat-sdk", selectedApprovalCard)
provenance:
- benchmark/typescript/nanoclaw/src/modules/approvals/primitive.ts
```
