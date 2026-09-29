# DroidClaw.executeClipboardSet or DroidClaw.copyVisibleText

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-0d6cb0f02394c7e0
api: DroidClaw.executeClipboardSet or DroidClaw.copyVisibleText
api_family: droidclaw.clipboard-write
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: droidclaw
  version: legacy-source-bound
capability_class: clipboard-write
normative_authority: capability-facts-only
bound_sinks:
- executeClipboardSet
- copyVisibleText
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
- facet_id: legacy-facet-c3925176
  capability: Replace the attached Android device's clipboard with model-provided text or text selected from visible UI elements by a model-provided query.
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
- default_id: legacy-default-8ebce96d
  role_id: null
  value: Clipboard text is shell-escaped before the ADB command; copyVisibleText may fall back to the selected visible element when its query does not directly provide the copied text.
  security_effect: Clipboard text is shell-escaped before the ADB command; copyVisibleText may fall back to the selected visible element when its query does not directly provide the copied text.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'executeClipboardSet({ action: "clipboard_set", text: "reviewed" })'
  capability_edge: 'copyVisibleText({ action: "copy_visible_text", query: modelQuery }, elements)'
provenance:
- benchmark/typescript/droidclaw/src/actions.ts
- benchmark/typescript/droidclaw/src/skills.ts
```
