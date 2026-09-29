# node:fs read primitives

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-f0032bb100116403
api: node:fs read primitives
api_family: node.fs.read
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: node
  version: legacy-source-bound
capability_class: file-read
normative_authority: capability-facts-only
bound_sinks:
- readFile
- readFileSync
- open
- openSync
roles:
- role_id: path
  description: Legacy controlled role path.
  bindings:
  - expression: path
    caller_bindable: true
facets:
- facet_id: legacy-facet-3bd64019
  capability: Read bytes or text from a caller-selected path with the agent process privileges, including files reached through absolute paths, parent traversal, or filesystem links.
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
- default_id: legacy-default-b71d5a32
  role_id: null
  value: Relative paths resolve against the process working directory; filesystem path resolution follows the host platform and symbolic links unless a higher layer constrains them.
  security_effect: Relative paths resolve against the process working directory; filesystem path resolution follows the host platform and symbolic links unless a higher layer constrains them.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: await fs.readFile(path.join(workspace, "README.md"), "utf8")
  capability_edge: await fs.readFile(selectedPath)
provenance:
- https://nodejs.org/api/fs.html
```
