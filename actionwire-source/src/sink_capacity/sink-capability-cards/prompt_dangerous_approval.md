# prompt_dangerous_approval

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-3cb5bb52267fed0a
api: prompt_dangerous_approval
api_family: prompt_dangerous_approval
runtime:
  language: python
  ecosystem: python-runtime
  package: prompt_dangerous_approval
  version: legacy-source-bound
capability_class: user-consent
normative_authority: capability-facts-only
bound_sinks:
- prompt_dangerous_approval
roles:
- role_id: command
  description: Legacy controlled role command.
  bindings:
  - expression: command
    caller_bindable: true
facets:
- facet_id: legacy-facet-50e55375
  capability: Presents a model-controlled command and its security description to an approval callback or interactive CLI, then returns the user's approval scope or denial to the command guard that controls later execution.
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
- default_id: legacy-default-6d1a6360
  role_id: null
  value: Only commands already classified as requiring approval reach this sink. Callback failures return deny. When prompt_toolkit owns the terminal and no callback is installed, the sink denies rather than waiting on invisible stdin. Decisions are once, session, always, or deny; allow_permanent can hide the always option.
  security_effect: Only commands already classified as requiring approval reach this sink. Callback failures return deny. When prompt_toolkit owns the terminal and no callback is installed, the sink denies rather than waiting on invisible stdin. Decisions are once, session, always, or deny; allow_permanent can hide the always option.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: "choice = prompt_dangerous_approval(\n    \"git status\", \"review requested\", allow_permanent=False\n)"
  capability_edge: "choice = prompt_dangerous_approval(\n    command, description, approval_callback=approval_callback\n)"
provenance:
- benchmark/python/hermes-agent/tools/approval.py:1000
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
