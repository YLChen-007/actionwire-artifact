# Jinja2 Environment.from_string

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-101c216a66107ed1
api: Jinja2 Environment.from_string
api_family: jinja2.from_string
runtime:
  language: python
  ecosystem: python-runtime
  package: jinja2
  version: legacy-source-bound
capability_class: template-injection
normative_authority: capability-facts-only
bound_sinks: []
roles:
- role_id: primary-input
  description: Legacy controlled role primary-input.
  bindings:
  - expression: primary
    caller_bindable: true
facets:
- facet_id: legacy-facet-cd0edb3f
  capability: Compile any template string into an executable Jinja2 Template object.
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-fca2f734
  capability: The compiled Template carries the full Jinja2 execution environment
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-a414069c
  capability: 'Render-time expression evaluation (`{{ ... }}`) can:'
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-0dd96042
  capability: Access any Python object reachable from template globals, filters, and tests
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-d7306e09
  capability: Traverse the full Python object hierarchy via `__class__`, `__mro__`,
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-b8ccd587
  capability: Reach `__builtins__` through globals of built-in Jinja2 objects
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-af25b2c6
  capability: Import arbitrary Python modules via `__builtins__['__import__']()` or
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-f80d0848
  capability: Execute arbitrary shell commands via `os.popen()`, `os.system()`,
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-32a70da8
  capability: Read and write the file system via `open()`, `os.read()`, `os.write()`,
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-1cfcde59
  capability: Read environment variables via `os.environ`, `os.getenv()`
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-b00ae139
  capability: Make outbound network requests by importing `urllib`, `http.client`,
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-4946b271
  capability: Spawn reverse shells, download and execute payloads, establish C2 channels
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-ba7bbafd
  capability: Create and manipulate Python in-memory objects (lists, dicts, sockets,
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-014125e4
  capability: Exfiltrate data by writing to files, making network requests, or
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-155e4084
  capability: 'Block-level control (`{% %}`) can:'
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-5fbd602f
  capability: Assign variables via `{% set %}` — build multi-step exploit chains
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-fd5900b4
  capability: Include other templates via `{% include %}` and `{% import %}` —
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-121509cf
  capability: Execute arbitrary Python via custom extensions registered on the
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-be9cd3c3
  capability: Loop over any iterable via `{% for %}` — enables traversal of
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-0dc9057a
  capability: Define macros via `{% macro %}` — reusable exploit primitives
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-78bf50c1
  capability: 'Filter-level access (`| filter`) can:'
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-6e43f0b9
  capability: Dynamically access attributes via `|attr()` — bypass static analysis
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-2dd7540d
  capability: Execute Python code through custom filters registered on the Environment
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-bb844e8d
  capability: The default Environment constructor sets `autoescape=False`, which means
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-57872f70
  capability: '`from_string()` accepts these additional keyword arguments that the'
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-7df76596
  capability: '`globals` — if exposed by the caller, can inject additional global'
  role_ids:
  - primary-input
  activation:
    any_of:
    - predicate: role-bound
      subject: primary-input
      operator: equals
      value: true
- facet_id: legacy-facet-df5879ff
  capability: The returned Template is a compiled code object — once compiled, it can be
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
- default_id: legacy-default-1508a7dd
  role_id: null
  value: '`autoescape=False` by default on `jinja2.Environment()` — template output'
  security_effect: '`autoescape=False` by default on `jinja2.Environment()` — template output'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-2bdf8a05
  role_id: null
  value: Template compilation resolves `{% extends %}`, `{% include %}`, and
  security_effect: Template compilation resolves `{% extends %}`, `{% include %}`, and
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-3f48f9f2
  role_id: null
  value: Template code executes in the SAME Python process with the SAME user
  security_effect: Template code executes in the SAME Python process with the SAME user
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-15240719
  role_id: null
  value: '`Environment()` caches compiled templates in memory by default'
  security_effect: '`Environment()` caches compiled templates in memory by default'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-fec5a5a5
  role_id: null
  value: Jinja2 3.1.6 (pinned in hermes-agent) still allows `__subclasses__()`
  security_effect: Jinja2 3.1.6 (pinned in hermes-agent) still allows `__subclasses__()`
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-34994ec8
  role_id: null
  value: The `SandboxedEnvironment` subclass IS available but is opt-in;
  security_effect: The `SandboxedEnvironment` subclass IS available but is opt-in;
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-40b50ac8
  role_id: null
  value: Jinja2 resolves names at render time through the template context chain
  security_effect: Jinja2 resolves names at render time through the template context chain
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: See the source-owned legacy card for the original benign example.
  capability_edge: See the source-owned legacy card for the original capability-edge example.
provenance:
- source-owned legacy capability card
```
