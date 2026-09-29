# Playwright page.evaluate or locator.evaluate

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-2a7752986b2cb0d8
api: Playwright page.evaluate or locator.evaluate
api_family: openclaw-cn.code-eval
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: openclaw-cn
  version: legacy-source-bound
capability_class: code-eval
normative_authority: capability-facts-only
bound_sinks:
- page.evaluate
- locator.evaluate
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: text
    caller_bindable: true
facets:
- facet_id: legacy-facet-75078602
  capability: Evaluate a model-selected JavaScript function body in the active page or selected element context.
  role_ids:
  - content
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-c814ff42
  role_id: null
  value: The page origin, authenticated browser state, selected element, and browser permissions bound the evaluated code.
  security_effect: The page origin, authenticated browser state, selected element, and browser permissions bound the evaluated code.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: await page.evaluate(browserEvaluator, "() => document.title")
  capability_edge: await page.evaluate(browserEvaluator, selectedFunctionText)
provenance:
- benchmark/typescript/openclaw-cn/src/browser/pw-tools-core.interactions.ts
```
