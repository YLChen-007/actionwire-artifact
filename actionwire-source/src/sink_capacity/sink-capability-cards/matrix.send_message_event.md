# mautrix.Client.send_message_event

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-37990982b0250006
api: mautrix.Client.send_message_event
api_family: matrix.send_message_event
runtime:
  language: python
  ecosystem: python-runtime
  package: matrix
  version: legacy-source-bound
capability_class: delivery-render
normative_authority: capability-facts-only
bound_sinks:
- client.send_message_event(room_id, event_type, content)
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: content
    caller_bindable: true
facets:
- facet_id: legacy-facet-cb5e6c4b
  capability: Deliver attacker-influenced text and formatted HTML into a Matrix room.
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
- default_id: legacy-default-8988a905
  role_id: null
  value: The configured bot identity and room permissions authorize the event; clients render formatted_body according to the event format.
  security_effect: The configured bot identity and room permissions authorize the event; clients render formatted_body according to the event format.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'await client.send_message_event(room, EventType.ROOM_MESSAGE, {''body'': ''hello''})'
  capability_edge: Unsanitized formatted_body can carry active links, mentions, or client-rendered HTML.
provenance:
- src/ql/call/sinks_af.qll Matrix delivery sink
```
