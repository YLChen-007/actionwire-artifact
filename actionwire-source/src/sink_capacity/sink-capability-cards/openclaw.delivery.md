# runMessageAction

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-2f554523a838578c
api: runMessageAction
api_family: openclaw.delivery
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: openclaw
  version: legacy-source-bound
capability_class: delivery
normative_authority: capability-facts-only
bound_sinks:
- runMessageAction
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: message
    caller_bindable: true
facets:
- facet_id: legacy-facet-4237d35c
  capability: Delegate a caller-selected outbound channel action, destination, text, and media payload to the configured channel implementation.
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
- default_id: legacy-default-2621d489
  role_id: null
  value: Configured accounts, credentials, current conversation context, platform formatting, mention parsing, and destination defaults determine delivery authority and rendered effects.
  security_effect: Configured accounts, credentials, current conversation context, platform formatting, mention parsing, and destination defaults determine delivery authority and rendered effects.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'runMessageAction({ action: "send", target: currentChat, message: "Done" }, config)'
  capability_edge: runMessageAction(selectedActionPayload, config)
provenance:
- benchmark/typescript/openclaw/src/agents/tools/message-tool.ts
```
