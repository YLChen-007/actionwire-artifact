# LettaCode.Read

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-2336b69af3a39720
api: LettaCode.Read
api_family: lettabot.file-read
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: lettabot
  version: legacy-source-bound
capability_class: file-read
normative_authority: capability-facts-only
bound_sinks:
- Read
roles:
- role_id: path
  description: Legacy controlled role path.
  bindings:
  - expression: path
    caller_bindable: true
facets:
- facet_id: legacy-facet-8b19b124
  capability: Read model-selected text or image files and return their content to the model.
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
- default_id: legacy-default-699e27d9
  role_id: null
  value: Relative paths resolve from USER_CWD or the process working directory; omitted line bounds use the built-in read limit.
  security_effect: Relative paths resolve from USER_CWD or the process working directory; omitted line bounds use the built-in read limit.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'Read({ file_path: "/workspace/README.md" })'
  capability_edge: 'Read({ file_path: modelPath, offset: modelOffset, limit: modelLimit })'
provenance:
- benchmark/typescript/lettabot/vendor-source/letta-code-v0.19.5/src/tools/impl/Read.ts
```
