# LettaCode.Grep

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-bbe5ae64f93eb953
api: LettaCode.Grep
api_family: lettabot.content-search
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: lettabot
  version: legacy-source-bound
capability_class: content-search
normative_authority: capability-facts-only
bound_sinks:
- Grep
roles:
- role_id: path
  description: Legacy controlled role path.
  bindings:
  - expression: path
    caller_bindable: true
facets:
- facet_id: legacy-facet-8a750f21
  capability: Search model-selected files and directories for a model-selected regular expression and return matching content, paths, or counts.
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
- default_id: legacy-default-d2fb1995
  role_id: null
  value: The path defaults to USER_CWD or the process working directory and output_mode defaults to files_with_matches.
  security_effect: The path defaults to USER_CWD or the process working directory and output_mode defaults to files_with_matches.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'Grep({ pattern: "TODO", path: "/workspace", glob: "*.ts" })'
  capability_edge: 'Grep({ pattern: modelPattern, path: modelPath, output_mode: modelMode })'
provenance:
- benchmark/typescript/lettabot/vendor-source/letta-code-v0.19.5/src/tools/impl/Grep.ts
```
