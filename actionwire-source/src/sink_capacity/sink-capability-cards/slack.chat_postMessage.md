# slack_sdk.WebClient.chat_postMessage

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-b753c99f2a446939
api: slack_sdk.WebClient.chat_postMessage
api_family: slack.chat_postMessage
runtime:
  language: python
  ecosystem: python-runtime
  package: slack
  version: legacy-source-bound
capability_class: delivery-render
normative_authority: capability-facts-only
bound_sinks:
- client.chat_postMessage(**kwargs)
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: text
    caller_bindable: true
facets:
- facet_id: legacy-facet-a353931c
  capability: Post caller-influenced content to a Slack channel as the configured bot.
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
- default_id: legacy-default-46f64f74
  role_id: null
  value: Slack mrkdwn parsing and mention expansion apply unless explicitly disabled or escaped.
  security_effect: Slack mrkdwn parsing and mention expansion apply unless explicitly disabled or escaped.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: client.chat_postMessage(channel='C123', text='hello')
  capability_edge: Unfiltered <!channel> or <!everyone> markup can create a mass mention.
provenance:
- src/ql/call/sinks_af.qll Slack delivery sink
```
