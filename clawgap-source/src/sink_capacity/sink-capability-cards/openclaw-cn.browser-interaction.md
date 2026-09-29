# Playwright locator click and double-click

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-351ac6801997a142
api: Playwright locator click and double-click
api_family: openclaw-cn.browser-interaction
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: openclaw-cn
  version: legacy-source-bound
capability_class: browser-interaction
normative_authority: capability-facts-only
bound_sinks:
- locator.click
- locator.dblclick
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-39b46b59
  capability: Activate a model-selected browser element, including UI actions that can submit state or trigger navigation.
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
- default_id: legacy-default-8800ea04
  role_id: null
  value: The current page, stored role-ref map, browser session, cookies, and event handlers determine the resulting effect.
  security_effect: The current page, stored role-ref map, browser session, cookies, and event handlers determine the resulting effect.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'await locator.click({ timeout: 8000 })'
  capability_edge: await locatorFromSelectedRef.click({ timeout })
provenance:
- benchmark/typescript/openclaw-cn/src/browser/pw-tools-core.interactions.ts
```
