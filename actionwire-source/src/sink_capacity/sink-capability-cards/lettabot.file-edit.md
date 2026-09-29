# LettaCode.Edit

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-924babebe2361659
api: LettaCode.Edit
api_family: lettabot.file-edit
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: lettabot
  version: legacy-source-bound
capability_class: file-edit
normative_authority: capability-facts-only
bound_sinks:
- Edit
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-a7719ee4
  capability: Replace model-selected text in a model-selected file and persist the modified content.
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
- default_id: legacy-default-b523a59d
  role_id: null
  value: Relative paths resolve from USER_CWD or the process working directory; replace_all defaults to false.
  security_effect: Relative paths resolve from USER_CWD or the process working directory; replace_all defaults to false.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'Edit({ file_path: "/workspace/app.ts", old_string: "old", new_string: "new" })'
  capability_edge: 'Edit({ file_path: modelPath, old_string: selectedText, new_string: modelText, replace_all: modelReplaceAll })'
provenance:
- benchmark/typescript/lettabot/vendor-source/letta-code-v0.19.5/src/tools/impl/Edit.ts
```
