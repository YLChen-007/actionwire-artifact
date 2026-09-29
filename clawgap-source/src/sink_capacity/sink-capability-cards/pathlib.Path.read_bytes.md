# pathlib.Path(...).read_bytes

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-24a852bf6b712e92
api: pathlib.Path(...).read_bytes
api_family: pathlib.Path.read_bytes
runtime:
  language: python
  ecosystem: python-runtime
  package: pathlib
  version: legacy-source-bound
capability_class: file-read
normative_authority: capability-facts-only
bound_sinks:
- Path(...).read_bytes()
roles:
- role_id: path
  description: Legacy controlled role path.
  bindings:
  - expression: file
    caller_bindable: true
  - expression: path
    caller_bindable: true
facets:
- facet_id: legacy-facet-d5aaa39e
  capability: Read the entire binary contents of any file on the local filesystem that the process has read permission for.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-28ad1373
  capability: Read files via absolute paths, bypassing any intended working-directory or base-path restriction.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-4db17dc6
  capability: Read files via relative path traversal (CWE-22) using `../` sequences to escape a base directory.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-8c0ed3b9
  capability: Read symbolic links transparently — symlinks are silently followed (POSIX open(2) resolution), so pointing at a symlink reads the ultimate target file.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-178c2e86
  capability: Read special device files and virtual filesystem entries (e.g., `/dev/sda`, `/dev/mem`, `/dev/tty` on Linux) as raw bytes if permissions allow.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-0c531e57
  capability: Read Linux `/proc/` filesystem entries to leak process memory, environment variables, command-line arguments, file descriptors, and runtime state (e.g., `/proc/self/environ`, `/proc/self/maps`, `/proc/self/fd/0`, `/proc/self/mem`, `/proc/1/cmdline`).
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-c817fa9c
  capability: Read kernel and hardware information via `/sys/` on Linux (e.g., `/sys/class/net/eth0/address` for MAC addresses).
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-887eb7bb
  capability: Read the entire file in one shot — no built-in size limit; a large file can exhaust process memory.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-2e773f77
  capability: Read files with any encoding or binary format (returns `bytes`, no encoding/decoding step).
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-81ee3ec9
  capability: Read named pipes (FIFOs) — blocks until a writer opens the other end.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-668bcfbd
  capability: Read `/etc/passwd`, `/etc/shadow` (if permissions allow), SSH private keys (`~/.ssh/id_rsa`), cloud metadata endpoints mounted as files, configuration files containing credentials, database files, and application secrets.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-8cf37abb
  capability: 'Read Windows-specific paths (on Windows hosts): registry hive files, SAM database, NTDS.dit, DPAPI master keys, browser cookie databases.'
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-0141e7d1
  capability: Combine with `Path.home()` or `~` expansion to enumerate and read user-home-directory files without knowing the exact username.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-e54f4f55
  capability: Combine with directory traversal or glob enumeration to discover then read files in a multi-step attack.
  role_ids:
  - path
  activation:
    any_of:
    - predicate: role-bound
      subject: path
      operator: equals
      value: true
- facet_id: legacy-facet-3fc03bfd
  capability: On containerized or cloud environments, read mounted secrets files (e.g., `/var/run/secrets/kubernetes.io/serviceaccount/token`, `/run/secrets/`, cloud-init metadata files).
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
- default_id: legacy-default-8ff2d3b0
  role_id: null
  value: Symlinks are ALWAYS followed — `read_bytes` calls `open()` under the hood with no `O_NOFOLLOW` flag; there is no parameter to disable symlink resolution.
  security_effect: Symlinks are ALWAYS followed — `read_bytes` calls `open()` under the hood with no `O_NOFOLLOW` flag; there is no parameter to disable symlink resolution.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-0d33960c
  role_id: null
  value: The file is opened in the calling process's effective UID/GID context — inherits all filesystem permissions of the process (including any `CAP_DAC_READ_SEARCH` or `sudo` escalation).
  security_effect: The file is opened in the calling process's effective UID/GID context — inherits all filesystem permissions of the process (including any `CAP_DAC_READ_SEARCH` or `sudo` escalation).
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-0f38c122
  role_id: null
  value: The process's current working directory is inherited — relative paths resolve relative to whatever `os.getcwd()` returns at call time.
  security_effect: The process's current working directory is inherited — relative paths resolve relative to whatever `os.getcwd()` returns at call time.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-5fb5ee86
  role_id: null
  value: The file is opened, read entirely, and closed atomically — no streaming or partial-read option; the whole file is loaded into a single bytes object.
  security_effect: The file is opened, read entirely, and closed atomically — no streaming or partial-read option; the whole file is loaded into a single bytes object.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-9cfa8098
  role_id: null
  value: No maximum read size — the method reads until EOF, consuming memory proportional to file size.
  security_effect: No maximum read size — the method reads until EOF, consuming memory proportional to file size.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-0711f862
  role_id: null
  value: File descriptors are consumed temporarily during the read and released after, so repeated calls against many files can exhaust the process's fd ulimit.
  security_effect: File descriptors are consumed temporarily during the read and released after, so repeated calls against many files can exhaust the process's fd ulimit.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-ed9b70e1
  role_id: null
  value: No path canonicalization — `Path("a/../b")` is NOT resolved to `Path("b")` before open; the OS filesystem resolves `..` at open time.
  security_effect: No path canonicalization — `Path("a/../b")` is NOT resolved to `Path("b")` before open; the OS filesystem resolves `..` at open time.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-2cfe1225
  role_id: null
  value: On Windows, path separators `/` and `\` are both accepted, and drive-relative paths (`C:foo` without `\`) resolve relative to the drive's current directory.
  security_effect: On Windows, path separators `/` and `\` are both accepted, and drive-relative paths (`C:foo` without `\`) resolve relative to the drive's current directory.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-5cfa4df3
  role_id: null
  value: The method raises `FileNotFoundError`, `PermissionError`, or `OSError` on failure — error messages may leak filesystem structure information.
  security_effect: The method raises `FileNotFoundError`, `PermissionError`, or `OSError` on failure — error messages may leak filesystem structure information.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'from pathlib import Path


    # Benign: read a known static file within the project

    config_bytes = Path("config/settings.json").read_bytes()

    print(f"Read {len(config_bytes)} bytes of config")

    '
  capability_edge: 'from pathlib import Path


    # Edge: path traversal escaping a base directory

    Path("../../etc/passwd").read_bytes()


    # Edge: absolute-path read of SSH private key

    Path("/root/.ssh/id_rsa").read_bytes()


    # Edge: read process environment via /proc (Linux)

    Path("/proc/self/environ").read_bytes()


    # Edge: follow a symlink to a target outside the intended directory

    Path("sandbox/link_to_secret").read_bytes()  # symlink → /etc/shadow

    '
provenance:
- https://docs.python.org/3/library/pathlib.html#pathlib.Path.read_bytes
- POSIX open(2) symlink resolution behavior
- '{''CWE-22'': "Improper Limitation of a Pathname to a Restricted Directory (''Path Traversal'')"}'
```
