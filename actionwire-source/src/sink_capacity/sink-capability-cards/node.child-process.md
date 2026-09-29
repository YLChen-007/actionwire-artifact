# node:child_process spawn/exec family

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-567d5b623a119cf2
api: node:child_process spawn/exec family
api_family: node.child-process
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: node
  version: legacy-source-bound
capability_class: process-spawn
normative_authority: capability-facts-only
bound_sinks:
- spawn
- spawnSync
- exec
- execSync
- execFile
- execFileSync
- fork
roles:
- role_id: command
  description: Legacy controlled role command.
  bindings:
  - expression: command
    caller_bindable: true
- role_id: environment
  description: Legacy controlled role environment.
  bindings:
  - expression: env
    caller_bindable: true
- role_id: working-directory
  description: Legacy controlled role working-directory.
  bindings:
  - expression: cwd
    caller_bindable: true
facets:
- facet_id: legacy-facet-aa874685
  capability: Execute a local process with caller-selected executable, arguments, environment, and working directory; exec-family calls may additionally interpret a command through a shell.
  role_ids:
  - command
  - environment
  - working-directory
  activation:
    any_of:
    - predicate: role-bound
      subject: command
      operator: equals
      value: true
    - predicate: role-bound
      subject: environment
      operator: equals
      value: true
    - predicate: role-bound
      subject: working-directory
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-c825512f
  role_id: null
  value: The child inherits the agent process privileges, environment, stdio policy, and current working directory unless the caller replaces them; platform command resolution and shell behavior can expand the effect.
  security_effect: The child inherits the agent process privileges, environment, stdio policy, and current working directory unless the caller replaces them; platform command resolution and shell behavior can expand the effect.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'spawn("git", ["status", "--short"], { cwd: workspace })'
  capability_edge: 'spawn(command, argv, { cwd: selectedDirectory, env: selectedEnvironment })'
provenance:
- https://nodejs.org/api/child_process.html
```
