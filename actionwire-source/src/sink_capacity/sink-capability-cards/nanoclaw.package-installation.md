# NanoClaw.install_packages

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-7f524cd635ebccbf
api: NanoClaw.install_packages
api_family: nanoclaw.package-installation
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: nanoclaw
  version: legacy-source-bound
capability_class: package-installation
normative_authority: capability-facts-only
bound_sinks:
- install_packages
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-57a9a5bf
  capability: Persist approved package selections, rebuild the agent image, and restart its container.
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
- default_id: legacy-default-3aa610fe
  role_id: null
  value: Package names are syntax-constrained, requests require approval, and at most 20 packages are accepted.
  security_effect: Package names are syntax-constrained, requests require approval, and at most 20 packages are accepted.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'install_packages({ apt: ["ripgrep"], reason: "search source" })'
  capability_edge: 'install_packages({ apt: modelApt, npm: modelNpm, reason: modelReason })'
provenance:
- benchmark/typescript/nanoclaw/src/modules/self-mod/apply.ts
```
