# PermissionManager.askHandler

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-087e5444416350de
api: PermissionManager.askHandler
api_family: mercury.command-approval
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: mercury
  version: legacy-source-bound
capability_class: user-consent
normative_authority: capability-facts-only
bound_sinks:
- askHandler
roles:
- role_id: command
  description: Legacy controlled role command.
  bindings:
  - expression: command
    caller_bindable: true
facets:
- facet_id: legacy-facet-6be9cf16
  capability: Presents a model-controlled shell command to the active Mercury channel and returns the user's approval decision to PermissionManager.checkShellCommand, which controls whether later command execution is allowed.
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
- default_id: legacy-default-696a184e
  role_id: null
  value: Commands classified as safe read-only return before this sink. A yes decision allows one command; always enables session-wide auto approval; every other response denies. When no callback is installed or the channel is internal, the guard returns needsApproval instead of treating the command as approved.
  security_effect: Commands classified as safe read-only return before this sink. A yes decision allows one command; always enables session-wide auto approval; every other response denies. When no callback is installed or the channel is internal, the guard returns needsApproval instead of treating the command as approved.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'const result = await askHandler("Run command: git status");'
  capability_edge: 'const result = await this.askHandler(`Run command: ${trimmed}`);'
provenance:
- benchmark/typescript/mercury-agent/src/capabilities/permissions.ts:513
policy_contract:
  schema_version: approval-policy-contract/v1
  boundary: dangerous-command-user-consent
  requirements:
  - policy_id: indirect-file-operands
    rule: A command classified as safe read-only must account for options that obtain file operands indirectly before bypassing approval.
    applicability: The approval bypass recognizes shell command names or textual patterns without resolving option-level file inputs.
    security_effect: Prevent unauthorized file reads through indirect operand sources.
    examples:
    - wc --files0-from=list.txt
  - policy_id: shell-expansion-semantics
    rule: Approval bypass classification must account for shell variable and glob expansion that changes the effective data read or disclosed.
    applicability: A shell-interpreted command is approved from its unexpanded text.
    security_effect: Prevent commands classified as benign from exposing expanded secrets.
    examples:
    - echo $SECRET
    - cat $HOME/.ssh/id_rsa
  - policy_id: redirection-effect
    rule: A command classified as read-only must not bypass approval when shell redirection changes its effective capability to file creation or mutation.
    applicability: The shell interprets output redirection after textual safe-read matching.
    security_effect: Prevent unauthorized file writes through read-like command names.
    examples:
    - echo value > target
    - cat input >> target
  - policy_id: command-action-semantics
    rule: Approval bypass classification must inspect action options that give a nominally read-oriented command execution or mutation capability.
    applicability: A command name is auto-approved without interpreting action flags.
    security_effect: Prevent command execution or deletion through unsafe action options.
    examples:
    - find . -exec sh -c payload \;
    - find . -delete
```
