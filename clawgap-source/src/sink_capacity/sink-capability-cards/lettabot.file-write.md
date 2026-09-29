# LettaCode.Write

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-31222bd945fb91ae
api: LettaCode.Write
api_family: lettabot.file-write
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: lettabot
  version: legacy-source-bound
capability_class: file-write
normative_authority: capability-facts-only
bound_sinks:
- Write
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: content
    caller_bindable: true
facets:
- facet_id: legacy-facet-fa17f4c3
  capability: Create or overwrite a model-selected file with model-selected content.
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
- default_id: legacy-default-d7ef5a7e
  role_id: null
  value: Parent directories are created recursively; relative paths resolve from USER_CWD or the process working directory.
  security_effect: Parent directories are created recursively; relative paths resolve from USER_CWD or the process working directory.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'Write({ file_path: "/workspace/notes.txt", content: "done" })'
  capability_edge: 'Write({ file_path: modelPath, content: modelContent })'
provenance:
- benchmark/typescript/lettabot/vendor-source/letta-code-v0.19.5/src/tools/impl/Write.ts
```
