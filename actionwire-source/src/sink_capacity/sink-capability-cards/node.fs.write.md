# node:fs write primitives

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-424e959c43e5fc42
api: node:fs write primitives
api_family: node.fs.write
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: node
  version: legacy-source-bound
capability_class: file-write
normative_authority: capability-facts-only
bound_sinks:
- writeFile
- writeFileSync
- appendFile
- appendFileSync
- copyFile
- copyFileSync
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: content
    caller_bindable: true
- role_id: path
  description: Legacy controlled role path.
  bindings:
  - expression: path
    caller_bindable: true
facets:
- facet_id: legacy-facet-978be076
  capability: Create, replace, append, or copy caller-selected content at caller-selected filesystem paths.
  role_ids:
  - content
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-aa9f4c50
  role_id: null
  value: Existing files may be overwritten under the agent process privileges; relative paths and filesystem links use host resolution, and writeFile creates a missing file by default.
  security_effect: Existing files may be overwritten under the agent process privileges; relative paths and filesystem links use host resolution, and writeFile creates a missing file by default.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: await fs.writeFile(path.join(workspace, "notes.txt"), content, "utf8")
  capability_edge: await fs.writeFile(selectedPath, selectedContent)
provenance:
- https://nodejs.org/api/fs.html
```
