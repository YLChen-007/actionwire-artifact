# LettaCode.Glob

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-ce0cc7bca70de276
api: LettaCode.Glob
api_family: lettabot.file-enumeration
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: lettabot
  version: legacy-source-bound
capability_class: file-enumeration
normative_authority: capability-facts-only
bound_sinks:
- Glob
roles:
- role_id: path
  description: Legacy controlled role path.
  bindings:
  - expression: path
    caller_bindable: true
facets:
- facet_id: legacy-facet-f0731a2f
  capability: Enumerate files beneath a model-selected directory that match a model-selected glob pattern.
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
- default_id: legacy-default-e128143b
  role_id: null
  value: The search path defaults to USER_CWD or the process working directory; hidden files and followed symbolic links are included.
  security_effect: The search path defaults to USER_CWD or the process working directory; hidden files and followed symbolic links are included.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'Glob({ pattern: "**/*.ts", path: "/workspace" })'
  capability_edge: 'Glob({ pattern: modelPattern, path: modelPath })'
provenance:
- benchmark/typescript/lettabot/vendor-source/letta-code-v0.19.5/src/tools/impl/Glob.ts
```
