# DroidClaw.executePushFile

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-4b7a25b1d1e2adb3
api: DroidClaw.executePushFile
api_family: droidclaw.device-file-push
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: droidclaw
  version: legacy-source-bound
capability_class: device-file-push
normative_authority: capability-facts-only
bound_sinks:
- executePushFile
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-b5d31168
  capability: Copy a model-selected host file to a model-selected path on the attached Android device.
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-d809cc04
  role_id: null
  value: Both endpoints are supplied by the action; host filesystem and ADB device permissions determine which paths can be read or written.
  security_effect: Both endpoints are supplied by the action; host filesystem and ADB device permissions determine which paths can be read or written.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'executePushFile({ action: "push_file", source: "./review.txt", dest: "/sdcard/review.txt" })'
  capability_edge: 'executePushFile({ action: "push_file", source: modelSource, dest: modelDest })'
provenance:
- benchmark/typescript/droidclaw/src/actions.ts
```
