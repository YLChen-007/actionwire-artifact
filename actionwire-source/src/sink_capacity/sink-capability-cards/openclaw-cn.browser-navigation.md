# Playwright page.goto, CDP Target.createTarget, or Chrome /json/new

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-ff52757a722451b0
api: Playwright page.goto, CDP Target.createTarget, or Chrome /json/new
api_family: openclaw-cn.browser-navigation
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: openclaw-cn
  version: legacy-source-bound
capability_class: browser-navigation
normative_authority: capability-facts-only
bound_sinks:
- page.goto
- CDP.Target.createTarget
- fetch:/json/new
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: url
    caller_bindable: true
facets:
- facet_id: legacy-facet-b79e1f83
  capability: Create or navigate a browser tab to a model-selected URL in the configured browser profile.
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-70d87b4a
  role_id: null
  value: The profile can carry authenticated state and ambient network or local-file access; the navigation guard and browser runtime determine which URL schemes and destinations are accepted.
  security_effect: The profile can carry authenticated state and ambient network or local-file access; the navigation guard and browser runtime determine which URL schemes and destinations are accepted.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: await page.goto("https://example.com")
  capability_edge: await page.goto(selectedUrl)
provenance:
- benchmark/typescript/openclaw-cn/src/browser
```
