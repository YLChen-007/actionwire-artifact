# DroidClaw.executePullFile

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-862b4deaffe9e20e
api: DroidClaw.executePullFile
api_family: droidclaw.device-file-pull
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: droidclaw
  version: legacy-source-bound
capability_class: device-file-pull
normative_authority: capability-facts-only
bound_sinks:
- executePullFile
roles:
- role_id: path
  description: Legacy controlled role path.
  bindings:
  - expression: path
    caller_bindable: true
facets:
- facet_id: legacy-facet-fd42cb8f
  capability: Read a model-selected path from the attached Android device and copy it into DroidClaw's host-side pulled_files directory.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-41001c86
  role_id: null
  value: The destination directory is fixed while the output filename is derived from the selected device path; ADB permissions determine which device files can be read.
  security_effect: The destination directory is fixed while the output filename is derived from the selected device path; ADB permissions determine which device files can be read.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'executePullFile({ action: "pull_file", path: "/sdcard/review.txt" })'
  capability_edge: 'executePullFile({ action: "pull_file", path: modelDevicePath })'
provenance:
- benchmark/typescript/droidclaw/src/actions.ts
```
