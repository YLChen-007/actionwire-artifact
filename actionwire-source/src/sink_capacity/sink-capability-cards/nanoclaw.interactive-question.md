# NanoClaw.ask_user_question

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-9efc50c4d1352fcf
api: NanoClaw.ask_user_question
api_family: nanoclaw.interactive-question
runtime:
  language: typescript
  ecosystem: node-or-project-source
  package: nanoclaw
  version: legacy-source-bound
capability_class: interactive-question
normative_authority: capability-facts-only
bound_sinks:
- ask_user_question
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-f908c1dc
  capability: Present a model-defined multiple-choice question and wait for the selected response.
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
- default_id: legacy-default-8b360dc6
  role_id: null
  value: The current session supplies routing and the response wait defaults to 300 seconds.
  security_effect: The current session supplies routing and the response wait defaults to 300 seconds.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'ask_user_question({ title: "Confirm", question: "Continue?", options: ["Yes", "No"] })'
  capability_edge: ask_user_question(modelSelectedCard)
provenance:
- benchmark/typescript/nanoclaw/container/agent-runner/src/mcp-tools/interactive.ts
```
