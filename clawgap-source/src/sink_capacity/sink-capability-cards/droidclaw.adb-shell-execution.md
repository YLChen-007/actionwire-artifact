# DroidClaw.executeShell

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-e618b49a9ca89c42
api: DroidClaw.executeShell
api_family: droidclaw.adb-shell-execution
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: droidclaw
  version: legacy-source-bound
capability_class: adb-shell-execution
normative_authority: capability-facts-only
bound_sinks:
- executeShell
roles:
- role_id: command
  description: Legacy controlled role command.
  bindings:
  - expression: command
    caller_bindable: true
facets:
- facet_id: legacy-facet-af00c729
  capability: Execute an arbitrary model-selected command through ADB shell on the attached Android device.
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
- default_id: legacy-default-98b3ceac
  role_id: null
  value: DroidClaw splits the command on spaces and prepends the ADB shell operation; no approval, allowlist, or deny-by-default command policy is applied after the non-empty check.
  security_effect: DroidClaw splits the command on spaces and prepends the ADB shell operation; no approval, allowlist, or deny-by-default command policy is applied after the non-empty check.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'executeShell({ action: "shell", command: "getprop ro.build.version.release" })'
  capability_edge: 'executeShell({ action: "shell", command: modelCommand })'
provenance:
- benchmark/typescript/droidclaw/src/actions.ts
```
