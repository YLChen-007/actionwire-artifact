# pathlib.Path.read_text

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-8c5d75ce52b2a9cf
api: pathlib.Path.read_text
api_family: pathlib.Path.read_text
runtime:
  language: python
  ecosystem: python-runtime
  package: pathlib
  version: legacy-source-bound
capability_class: file-read
normative_authority: capability-facts-only
bound_sinks:
- Path.open
- Path.read_bytes
roles:
- role_id: path
  description: Legacy controlled role path.
  bindings:
  - expression: file
    caller_bindable: true
  - expression: path
    caller_bindable: true
facets:
- facet_id: legacy-facet-4c63a3a5
  capability: Read the entire decoded text content of any file on the filesystem that the process has read permission for, resolving to an absolute path before the open(2) syscall.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-8534233e
  capability: Traverse directories via relative paths containing `..` segments (CWE-22 / path traversal), escaping any intended directory sandbox to reach sibling or parent-directory files.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-f3ffab0c
  capability: Read files via absolute paths (`/etc/passwd`, `/etc/shadow`, etc.), bypassing any working-directory-based confinement entirely.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-59a4dbf7
  capability: 'Read files via symlinks: the underlying OS open(2) call follows symbolic links by default (without O_NOFOLLOW), so a symlink pointing to a sensitive file outside the intended directory tree is transparently resolved and read.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-2006ae72
  capability: 'Read special virtual-filesystem entries on Linux, including:'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-c3667708
  capability: '`/proc/self/environ` — process environment variables (often contains secrets, API keys, database URLs).'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-07b01af3
  capability: '`/proc/self/cmdline` — full command line of the running process.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-9d0a8249
  capability: '`/proc/self/maps` — memory mappings of the process.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-75e3de46
  capability: '`/proc/self/fd/<N>` — contents of any open file descriptor owned by the process.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-ddcee8cb
  capability: '`/proc/self/cwd` — symlink to the current working directory (leaks cwd path).'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-7cdb3152
  capability: '`/proc/self/exe` — symlink to the process binary (can be read for binary inspection).'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-98662ee9
  capability: '`/proc/self/status`, `/proc/self/stat`, `/proc/self/limits` — process metadata.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-3a15e43e
  capability: '`/proc/self/mountinfo`, `/proc/self/mounts` — mount table (reveals filesystem layout).'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-85c73040
  capability: '`/proc/self/net/tcp`, `/proc/self/net/udp` — network connection information.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-1b23c37d
  capability: '`/proc/version`, `/proc/cpuinfo`, `/proc/meminfo` — system information.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-a2771e61
  capability: '`/sys/class/net/<iface>/address` — MAC addresses.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-970d4f55
  capability: '`/sys/class/dmi/id/product_uuid` — hardware UUID.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-b251f9b2
  capability: Read device files that behave like regular files when opened in text mode, e.g. `/dev/stdin` (reads from the process stdin stream, potentially consuming input intended for the application).
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-7c8f7662
  capability: Block indefinitely when the path points to a named pipe (FIFO) or a blocking device file whose read never completes.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-9c63136e
  capability: 'The attacker controls the `encoding` parameter: can specify any codec registered in Python (`utf-8`, `latin-1`, `ascii`, `utf-16`, `utf-32`, `cp1252`, `shift_jis`, etc.). Using `latin-1` reads every byte 1:1 without decode errors, enabling extraction of arbitrary binary file content as text.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-56d0e560
  capability: 'The attacker controls the `errors` parameter, with the following sub-capabilities:'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-c5349e9d
  capability: '`''strict''` (default): normal decode; `UnicodeDecodeError` on invalid bytes may leak information about file encoding through exception messages.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-9d7d0a3e
  capability: '`''ignore''`: silently drops undecodable bytes, hiding corruption but still returning the readable portion of a binary file.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-3825ed54
  capability: '`''replace''`: replaces undecodable bytes with the U+FFFD replacement character, making binary content readable with loss markers.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-f1193e31
  capability: '`''surrogateescape''`: encodes undecodable bytes as lone surrogates (U+DC80–U+DCFF), preserving the original byte values in-band within a Unicode string — the result can be round-tripped back to the original bytes, effectively allowing binary exfiltration through a text-typed return value.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-44fb9dc5
  capability: '`''backslashreplace''`: replaces undecodable bytes with `\xNN` escape sequences, revealing exact byte values in readable form.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-4a3c7838
  capability: '`''xmlcharrefreplace''`: replaces undecodable bytes with XML numeric character references (`&#NN;`).'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-383fc2be
  capability: 'The attacker controls the `newline` parameter (Python ≥ 3.13), with the following sub-capabilities:'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-4325a33d
  capability: '`None` (default): universal newline mode — `\r\n`, `\r`, and `\n` are all translated to `\n`, potentially normalizing file content and altering line counts.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-a0c26d43
  capability: '`''''`: no newline translation; file content returned as-is.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-c974f1e3
  capability: '`''\n''`, `''\r''`, `''\r\n''`: only the specified sequence triggers a line break; others pass through.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-00b9695f
  capability: The `read_text` call opens and then closes the file, so each invocation consumes one file descriptor for the duration of the read. Repeated reads can probe many files.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-ba4d21da
  role_id: null
  value: The file is opened in text mode (not binary); use `Path.read_bytes` for raw binary access.
  security_effect: The file is opened in text mode (not binary); use `Path.read_bytes` for raw binary access.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-78c99141
  role_id: null
  value: Symlinks are followed silently — the OS-level open(2) syscall does not use O_NOFOLLOW.
  security_effect: Symlinks are followed silently — the OS-level open(2) syscall does not use O_NOFOLLOW.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-61aba67c
  role_id: null
  value: 'Universal newline mode is active by default (`newline=None`): all common line endings are normalized to `\n`.'
  security_effect: 'Universal newline mode is active by default (`newline=None`): all common line endings are normalized to `\n`.'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-c8d0b919
  role_id: null
  value: Default encoding is `None`, which resolves to `locale.getpreferredencoding(False)` — typically UTF-8 on modern Linux/macOS, potentially a legacy code page on Windows.
  security_effect: Default encoding is `None`, which resolves to `locale.getpreferredencoding(False)` — typically UTF-8 on modern Linux/macOS, potentially a legacy code page on Windows.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-43059c22
  role_id: null
  value: Default error handling is `'strict'`, which raises `UnicodeDecodeError` if the file contains bytes not valid in the detected encoding.
  security_effect: Default error handling is `'strict'`, which raises `UnicodeDecodeError` if the file contains bytes not valid in the detected encoding.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-138ada18
  role_id: null
  value: The entire file content is loaded into memory as a single string — no streaming or chunking is available through this API.
  security_effect: The entire file content is loaded into memory as a single string — no streaming or chunking is available through this API.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-7288d18d
  role_id: null
  value: Path resolution is relative to the process's current working directory (`os.getcwd()`), an inherited environment variable that may differ from what the caller assumes.
  security_effect: Path resolution is relative to the process's current working directory (`os.getcwd()`), an inherited environment variable that may differ from what the caller assumes.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-a9876609
  role_id: null
  value: The method uses Python's built-in `open()` internally, which inherits whatever umask, locale, and filesystem encoding environment the process has.
  security_effect: The method uses Python's built-in `open()` internally, which inherits whatever umask, locale, and filesystem encoding environment the process has.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'from pathlib import Path


    # Read a known config file

    content = Path("config/settings.json").read_text()

    print(content)


    # Read with explicit encoding

    content = Path("data.csv").read_text(encoding="utf-8")

    '
  capability_edge: "from pathlib import Path\n\n# 1. Absolute path to a sensitive system file\nshadow_hash = Path(\"/etc/shadow\").read_text()\n\n# 2. Path traversal out of sandbox\nenv_secrets = Path(\"uploads/../../../etc/passwd\").read_text()\n\n# 3. Procfs environment leaking (API keys, DB creds)\nproc_env = Path(\"/proc/self/environ\").read_text(errors=\"surrogateescape\")\n\n# 4. Source code exfiltration via absolute path\napp_source = Path(\"/app/main.py\").read_text()\n\n# 5. Binary file extraction as text via latin-1 (1:1 byte mapping)\nbinary_content = Path(\"/app/encrypted.bin\").read_text(encoding=\"latin-1\")\n\n# 6. Symlink following to a target outside intended tree\n# (if /tmp/secret_link -> /etc/shadow)\nvia_symlink = Path(\"/tmp/secret_link\").read_text()\n\n# 7. Read another open fd's content (fd 3 = database socket or log pipe)\nfd_content = Path(\"/proc/self/fd/3\").read_text()\n\n# 8. Surrogate-escape for lossless binary-as-text exfiltration\nraw_bytes_as_str = Path(\"\
    /app/secret.key\").read_text(\n    encoding=\"ascii\", errors=\"surrogateescape\"\n)\n# raw_bytes_as_str.encode(\"ascii\", errors=\"surrogateescape\") recovers original bytes\n"
provenance:
- https://docs.python.org/3/library/pathlib.html#pathlib.Path.read_text
- 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory (''Path Traversal'')'
- 'POSIX open(2): symlink resolution is inherent; O_NOFOLLOW must be explicitly requested for the syscall to fail on symlinks.'
- 'Python 3.13 What''s New: newline parameter added to Path.read_text.'
- 'Python codecs module: surrogateescape error handler preserves raw bytes in-band — https://docs.python.org/3/library/codecs.html#error-handlers'
```
