# DroidClaw.composeEmail

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-90cfb4b020f66d3a
api: DroidClaw.composeEmail
api_family: droidclaw.email-compose
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: droidclaw
  version: legacy-source-bound
capability_class: email-compose
normative_authority: capability-facts-only
bound_sinks:
- composeEmail
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: text
    caller_bindable: true
- role_id: statement
  description: Legacy controlled role statement.
  bindings:
  - expression: query
    caller_bindable: true
facets:
- facet_id: legacy-facet-69b7455e
  capability: Open an Android email composer and populate its recipient and message content from a model-selected decision and matching visible UI context.
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-35136721
  role_id: null
  value: Android resolves the SENDTO intent to an installed mail application; the user and application retain the final send action and ambient account state.
  security_effect: Android resolves the SENDTO intent to an installed mail application; the user and application retain the final send action and ambient account state.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: composeEmail(reviewedDecision, visibleElements)
  capability_edge: 'composeEmail({ action: "compose_email", query: modelRecipient, text: modelBody }, elements)'
provenance:
- benchmark/typescript/droidclaw/src/skills.ts
```
