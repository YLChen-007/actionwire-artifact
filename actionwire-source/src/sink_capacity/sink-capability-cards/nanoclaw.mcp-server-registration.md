# NanoClaw.add_mcp_server

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-557ab746d0b69f77
api: NanoClaw.add_mcp_server
api_family: nanoclaw.mcp-server-registration
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: nanoclaw
  version: legacy-source-bound
capability_class: mcp-server-registration
normative_authority: capability-facts-only
bound_sinks:
- add_mcp_server
roles:
- role_id: command
  description: Legacy controlled role command.
  bindings:
  - expression: command
    caller_bindable: true
facets:
- facet_id: legacy-facet-af8c29de
  capability: Persist an approved external MCP server definition and restart the container so its tools become available.
  role_ids:
  - command
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-f100eb1f
  role_id: null
  value: Arguments and environment default to empty values; an administrator must approve the request before application.
  security_effect: Arguments and environment default to empty values; an administrator must approve the request before application.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'add_mcp_server({ name: "memory", command: "pnpm", args: ["dlx", "server-memory"] })'
  capability_edge: 'add_mcp_server({ name: modelName, command: modelCommand, args: modelArgs, env: modelEnv })'
provenance:
- benchmark/typescript/nanoclaw/src/modules/self-mod/apply.ts
```
