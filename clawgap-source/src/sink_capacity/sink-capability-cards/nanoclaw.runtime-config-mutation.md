# better-sqlite3.Statement.run:container_configs.mcp_servers

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-a725a098a4a42b99
api: better-sqlite3.Statement.run:container_configs.mcp_servers
api_family: nanoclaw.runtime-config-mutation
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: nanoclaw
  version: legacy-source-bound
capability_class: runtime-config-mutation
normative_authority: capability-facts-only
bound_sinks:
- Statement.run:container_configs
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-6c32fb0c
  capability: Replace an agent group's persisted MCP-server runtime configuration, including executable command, arguments, and environment values consumed by later container runs.
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
- default_id: legacy-default-98151d93
  role_id: null
  value: The serialized object becomes the complete mcp_servers column value and is used when NanoClaw builds the agent runtime configuration.
  security_effect: The serialized object becomes the complete mcp_servers column value and is used when NanoClaw builds the agent runtime configuration.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: updateContainerConfigJson(groupId, "mcp_servers", reviewedServers)
  capability_edge: statement.run(JSON.stringify(modelControlledServers), now, groupId)
provenance:
- benchmark/typescript/nanoclaw/src/db/container-configs.ts
```
