# ClawGap source artifact

This is a snapshot of the current tool source and its supporting specifications,
fixtures, configurations, and selected helper scripts. It preserves the source
layout and implementation bytes. It is not the full paper reproduction dataset.

## Package contents and provenance

- `src/`: current implementation, schemas, prompts, capability cards, documentation
  snapshots, resources, and tests. Versioned modules remain because the current
  implementation still imports them; filenames do not imply disposable backups.
- `scripts/`: current regression/maintenance entrypoints and helpers referenced by
  the retained code and tests. Their presence does not make external data available.
- Selected `design/` files: governing specifications, handler inventories for the
  12 registered projects, and Python helpers needed by retained entrypoints/tests.
- `SOURCE-MANIFEST.json`: per-file source hashes and selection reasons, Git HEAD,
  and eligible untracked/modified files. This is a working-tree snapshot, not a
  claim that all included files are committed at HEAD.
- `FILES.txt` and `SHA256SUMS`: full file inventory and per-file checksums.
- `ENVIRONMENT.json`: observed runtime and dependency versions.

Benchmark source, CodeQL databases/binaries, result datasets, GT corpora and
acceptance data, historical run directories, the paper, Git metadata, local agent
configuration, real credentials, caches, and installed dependencies are excluded.
`AGENTS.md` and `CLAUDE.md` are explicitly excluded. Existing licensing notices in
retained files are preserved; this package does not assign a new license.

## Installation

Run the following commands from the extracted `clawgap-source/` directory.
The inspected environment used Python 3.13.9, Node 22.22.0, and npm 10.9.4.
These are environment records, not verified minimum supported versions.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-artifact.txt
npm ci --prefix src/gate_semantics/lsp
```

The Python requirements pin direct dependencies; transitive Python dependencies
are not fully locked. `tiktoken==0.8.0` is optional for token estimation. The Node
package lock is preserved. Dependencies of analyzed projects must be installed
separately in their own environments.

Static CodeQL operations additionally require CodeQL CLI 2.22.1. Install it from
GitHub's official distribution under the applicable license, then expose its
executable at `bin/codeql` (for example, a symlink to your installation). The
original QL pack files are included unchanged. Their dependency ranges are `*`
and lock dependency maps are empty; the observed library versions are recorded in
`ENVIRONMENT.json`, but no complete CodeQL dependency lock is claimed.

Real LLM calls require operator-supplied credentials via the environment variable
named by the configuration (`DEEPSEEK_API_KEY` by default). No real API key is
included. Local mock/fixture credential strings and redaction-test inputs remain
as test data. Never put a real key into files you redistribute.

## Checks that do not require research data

Verify the extracted file contents before installing dependencies:

```bash
sha256sum -c SHA256SUMS
```

After installing the Python dependencies, these help commands check CLI loading
without calling an LLM or analyzing a target:

```bash
python -B -m src.pipeline --help
python -B -m src.handler_specifications --help
python -B -m src.sink_capacity.main --help
python -B -m src.gate_semantics.main --help
python -B -m src.group_oracle --help
python -B -m src.coverage_comparison --help
```

The release is independently extracted and checked for inventory/checksum
agreement, Python syntax, regular-file-only archive entries, credential patterns,
and the known locally configured API key. The release validation report is
provided beside the archive. These checks do not establish end-to-end execution,
complete dependency installation, or paper-result reproduction.

## External inputs and current limitations

- Static/semantic stages require revision-matched target source and CodeQL
  databases. `src/projects/registry.py` defines default locations and identities;
  the pipeline CLI exposes source/database/design/output/revision overrides.
- The current `src.coverage_comparison` canonical entrypoint requires an existing
  coverage manifest and frozen artifacts. Its v15 path validates that publication.
  It is not a fresh, data-free detector entrypoint; without the excluded output
  dataset it will report a missing manifest.
- Group-oracle, alignment, baseline evaluation, and runtime modules require their
  corresponding upstream artifacts or separately provisioned environments. Some
  retained evidence/configuration records reference excluded source or GT data.
- `python scripts/test_ql.py`, including `--unit-only`, is not a self-contained
  source-package test suite. It includes checks that need baseline/acceptance JSON,
  GT records, benchmark files, and generated outputs. Other tests with external
  dependencies include handler `RegisteredProjectSnapshots`, Hermes
  `RepositoryBaselineSmokeTest`, real-project call-chain tests, coverage
  `test_same_origin`, and runtime reporting integration tests. Full CodeQL/project
  regressions and live LLM/runtime campaigns are not run for this packaging task.
- Some legacy defaults and documentation still name the original machine's paths.
  Supply supported explicit paths or restore the expected external layout before
  using those entrypoints. Source files are not rewritten during packaging.
- `docs-map.yaml` is retained unchanged. It documents a larger research repository;
  entries describing excluded generated reports/data are not a promise that those
  outputs are present in this package. Some research-document cross-links therefore
  refer to material outside this source-only release.
