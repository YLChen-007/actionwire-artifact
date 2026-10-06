# Running the ActionWire Source Artifact

This guide describes the ActionWire source artifact. ActionWire combines CodeQL
analysis, tool-interface extraction, and LLM-assisted analysis of security
checks in agent software.

The `actionwire-source/` directory holds the current tool source, configuration,
capability cards, selected specifications, and tests. Target repositories, CodeQL
databases and binaries, research results, ground-truth datasets, and real API keys
are supplied separately. You can install the tool dependencies and run the checks
below using this source tree alone. Running analysis stages requires the
additional inputs listed later in this guide.

The commands below assume **Linux and Bash** and run from the
`actionwire-source/` directory.

## 1. Verify the checkout

The source tree is committed directly in this repository, so no archive needs to
be unpacked. Verify the file contents before installing dependencies or modifying
files:

```bash
cd actionwire-source
sha256sum -c SHA256SUMS
```

Every entry should report `OK`. `FILES.txt` lists the files; `SOURCE-MANIFEST.json`
records their origin and hashes.

## 2. Install the tool dependencies

The inspected environment used these versions:

| Component | Version |
|---|---|
| Python | 3.13.9 |
| Node.js | 22.22.0 |
| npm | 10.9.4 |
| CodeQL CLI, needed for static analysis | 2.22.1 |

These are the recorded environment versions, not tested minimum requirements.
Additional dependency versions are recorded in `ENVIRONMENT.json`.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-artifact.txt
npm ci --prefix src/gate_semantics/lsp
```

Python requirements pin the direct tool dependencies, but do not fully lock every
transitive dependency. The Node dependency lock is included. Installing these
dependencies requires access to the relevant package registries or a prepared
package cache.

The optional token estimator can be installed separately:

```bash
python -m pip install tiktoken==0.8.0
```

The tool has a fallback estimator when `tiktoken` is unavailable. Dependencies of
the analyzed projects belong in their own environments and are not covered by
`requirements-artifact.txt`.

## 3. Run a minimal check

These commands load the command-line interfaces without calling an LLM or
requiring a target repository:

```bash
python -B -m src.pipeline --help
python -B -m src.handler_specifications --help
python -B -m src.sink_capacity.main --help
python -B -m src.gate_semantics.main --help
python -B -m src.group_oracle --help
python -B -m src.coverage_comparison --help
```

Run the following self-contained tests:

```bash
python -B -m unittest \
  src.sink_capacity.tests.test_policy_contract \
  src.sink_capacity.tests.test_effective_capability \
  -v
```

Expected result: **9 tests, `OK`**. These tests use packaged capability cards and
in-memory fixtures. They do not require API keys, CodeQL, benchmark repositories,
ground truth, or previously generated results.

The six help commands and these nine tests passed in an independently extracted
copy using the existing Python 3.13.9 environment. Installation into a new virtual
environment has not been validated as part of this release.

## 4. Prepare a registered project for static analysis

### Install CodeQL

Install [CodeQL CLI 2.22.1](https://github.com/github/codeql-cli-binaries/releases/tag/v2.22.1)
for your platform. ActionWire expects the executable at `bin/codeql` inside the
`actionwire-source/` directory. Replace the example installation path below:

```bash
mkdir -p bin
ln -s /absolute/path/to/codeql/codeql bin/codeql
bin/codeql version
```

Having `codeql` on `PATH` alone does not satisfy this path requirement. If
`bin/codeql` already exists, check where it points before creating another link.

The recorded environment had the following CodeQL library packs available:

```bash
bin/codeql pack download \
  codeql/python-all@4.0.10 \
  codeql/javascript-all@2.6.6 \
  codeql/suite-helpers@1.0.26 \
  codeql/util@2.0.13
```

Run the download command if those versions are not already available. The original
`qlpack.yml` files use wildcard dependencies and the included lock files have
empty dependency maps. Downloading these versions does not establish a complete
dependency lock; other installed versions can affect resolution. Inspect available
packs with `bin/codeql resolve qlpacks` if resolution or compilation fails.

### Prepare matching source and database inputs

The current adapters support the projects registered in
`src/projects/registry.py`. List them with:

```bash
python -c 'from src.projects import list_projects; print("\n".join(list_projects()))'
```

The following example uses **NanoBot**, whose project ID is `nanobot`. First inspect
its configured input paths and analysis revision:

```bash
python - <<'PY'
from src.projects import get_project

spec = get_project("nanobot")
for name in (
    "analysis_revision", "source_root", "codeql_database", "output_root",
    "codeql_language", "extraction_exclusions", "extraction_inclusions",
):
    print(f"{name}: {getattr(spec, name)}")
PY
```

Obtain the matching project source snapshot separately and place it at
`benchmark/python/nanobot/`. Its source layout and revision must match the packaged
handler inventory in
`design/nanobot/handler-entry/debug/tool-handler-entries.csv`. Prepare a finalized
CodeQL database from that same snapshot at `codeql-db/nanobot-db/`.

For a clean NanoBot source tree with no installed dependencies or build outputs
inside it, the basic database creation command is:

```bash
bin/codeql database create codeql-db/nanobot-db \
  --language=python \
  --source-root=benchmark/python/nanobot
```

For other projects, apply the registry's extraction exclusions and inclusions and
use the corresponding language. TypeScript projects use CodeQL's `javascript`
language. Some adapters also depend on vendored source, so preserve the complete
analysis snapshot. A new database is not automatically equivalent to the frozen
database used for the paper.

The pipeline checks that the database identifies exactly the requested project
adapter. An arbitrary repository cannot be analyzed merely by assigning it an
existing project ID. Likewise, `--revision` labels analysis inputs; it does not
check out that revision or make inconsistent inputs compatible.

### Run tool-interface extraction and static analysis

After preparing the inputs above:

```bash
python -m src.handler_specifications --project nanobot
python -m src.pipeline --project nanobot infer-gates
python -m src.pipeline --project nanobot infer-call-chains
```

These commands do not call an LLM. Their main outputs are:

| Command | Main output under `output/nanobot/` |
|---|---|
| Handler specification extraction | `handler-specifications/tool-handler-specifications.json` and `.md` |
| `infer-gates` | `static/gates/` CSVs and manifest; `gate-semantics/gate-index.csv` and source slices |
| `infer-call-chains` | `static/call-chains/handler-sink-chains.csv`, `chain-gates.csv`, `sink-constraints.csv`, and manifest |

Run `infer-gates` before `infer-call-chains`. Do not expect the same output counts
when the source snapshot, database extraction, or library versions differ.

For an alternative directory layout, the pipeline accepts `--source-root`,
`--database`, `--design-root`, `--output-root`, and `--revision`. Keep the same
overrides across stages and place them **before** the stage subcommand. Handler
extraction has its own options: `--source-root`, `--handler-inventory`, `--revision`,
and `--output-directory`. A source-root override for handler extraction also
requires an explicit revision.

## 5. Run optional LLM-assisted gate analysis

This step needs the outputs of `infer-gates` and a working LLM account. It sends
source-derived context to the configured provider and consumes API credits.

Supply your own key through the environment. This Bash prompt avoids writing the
key into the command text:

```bash
read -r -s -p "DeepSeek API key: " DEEPSEEK_API_KEY
printf '\n'
export DEEPSEEK_API_KEY
```

Start with a limited gate selection:

```bash
python -m src.pipeline \
  --project nanobot \
  --llm-base-url https://api.deepseek.com/v1 \
  --model deepseek-v4-flash \
  infer-gate-semantics --max-gates 1 --timeout 900
```

Results are written under `output/nanobot/gate-semantics/`. `--max-gates 1` limits
the selected gates; it does not guarantee one API request or a fixed charge.
Validation, repair, and transport retries can require additional requests. The
timeout is not a total campaign budget.

The pipeline command above uses an OpenAI-compatible HTTP client. The standalone
`src.gate_semantics.main` and `src.sink_capacity.main` interfaces use different
agent backends and configuration. In particular, capability-card generation uses
the Claude CLI and an Anthropic-compatible endpoint. The source tree already
contains capability cards; regenerating them is not required for the example
above. Consult the relevant module README and `--help` before using those
interfaces.

To remove the key from the current shell after use:

```bash
unset DEEPSEEK_API_KEY
```

## 6. Understand the remaining pipeline requirements

### Call-chain semantic assembly

`infer-call-chain-semantics` additionally requires matching handler specifications
and this file:

```text
output/nanobot/handler-impact/handler-impact.jsonl
```

The source tree does not include the research handler-impact dataset, and the
current packaged CLI has no `infer-handler-impact` subcommand. Obtain compatible
handler-impact records separately before running:

```bash
python -m src.pipeline --project nanobot infer-call-chain-semantics
```

This also requires the preceding static artifacts and gate semantics for the
chains being assembled. Results are written under
`output/nanobot/call-chain-semantics/`.

`python -m src.pipeline --project nanobot all` only sequences the four pipeline
stages. It does not generate handler specifications or handler-impact records,
so it is not a complete first-run setup command for this source tree. It includes
`infer-gate-semantics`, which can send source context and consume API credits
before the final stage reports missing downstream inputs.

### Cross-project analysis and frozen coverage results

The following modules operate on the registered corpus and require additional
inputs. Their `--all` options do not mean “run the single project prepared above.”

| Module | Required inputs |
|---|---|
| `src.handler_type_alignment` | All registered projects' handler specifications and static call-chain/constraint artifacts; LLM configuration |
| `src.sink_type_alignment` | Handler alignment, per-project structural and semantic artifacts, and capability cards; LLM configuration or compatible replay records |
| `src.group_oracle` | Handler/sink alignment, per-project semantic artifacts, and evidence-registry source material; LLM configuration or compatible replay records |
| `src.coverage_comparison` | A compatible frozen coverage publication and all files/hashes required by its validator |

The current v15 coverage entrypoint validates an existing frozen publication. If
that dataset is supplied separately, restore its complete directory tree under
`output/cross-project/coverage-comparison/`, including `manifest.json` and all
referenced files. Copying the manifest alone is insufficient. Then run:

```bash
python -m src.coverage_comparison --all --replay-only
```

For a different dataset location, add `--out-dir /absolute/path/to/coverage-comparison`.
The supplied publication and referenced source/resources must still satisfy the
validator's version and hash checks.

Without the excluded dataset, `canonical coverage manifest is missing` is
expected. Neither `--analysis-plan` nor `--replay-only` creates the missing inputs.
Rebuilding arbitrary upstream outputs does not recreate the exact frozen
publication. The package therefore does not provide a data-free, one-command
reproduction of the paper's results.

Some inference commands expose `--stdout`; this previews their output but may
still perform inference. Check the module documentation before treating any
option as a dry run. Runtime-validation modules also need separately provisioned
target environments and are outside the setup example in this guide.

## 7. Troubleshooting

| Symptom | Check |
|---|---|
| `No module named src` | Run from the `actionwire-source/` directory. |
| Missing `jsonschema`, `yaml`, or SDK module | Activate the virtual environment and install `requirements-artifact.txt`. |
| Missing TypeScript compiler or language server | Run `npm ci --prefix src/gate_semantics/lsp`. |
| Missing `bin/codeql` | Create the expected executable link; setting `PATH` alone is insufficient. |
| CodeQL database missing or language/adapter mismatch | Use a finalized database for the selected registered project and matching source tree. |
| Missing gate CSVs or gate index | Complete `infer-gates` with the same output-root configuration first. |
| Missing `handler-impact.jsonl` | Supply the compatible external dataset; there is no packaged generator CLI for this step. |
| `canonical coverage manifest is missing` | Supply the frozen coverage dataset; it is deliberately absent from this source tree. |
| Repository-wide tests fail on missing GT/baseline/output files | Those are integration tests. Use the self-contained checks in section 3 for this source-only package. |

`python scripts/test_ql.py`, including `--unit-only`, includes tests that require
external benchmark, baseline, ground-truth, or generated-result files. It is not
the minimal installation check. Full CodeQL regressions, live LLM requests, target
runtime campaigns, and end-to-end paper reproduction were not performed when
validating this source release.

## Repository layout

```text
.
├── README.md                      # This guide
├── study/                         # Study dataset for the paper's empirical study
│   └── study-paper-data.xlsx      # One vulnerability per row (97 records) + field guide
└── actionwire-source/             # The source tree (browse directly; no unpacking)
    ├── README.md                  # Original packaged release notes
    ├── requirements-artifact.txt
    ├── ENVIRONMENT.json
    ├── FILES.txt
    ├── SHA256SUMS
    ├── SOURCE-MANIFEST.json
    ├── docs-map.yaml
    ├── src/                       # Tool implementation, resources, and tests
    ├── scripts/                   # Selected test and maintenance helpers
    └── design/                    # Selected specifications, inputs, and helpers
```

The source tree is served as ordinary files, so it can be browsed, cloned, or
downloaded directly from this repository. `actionwire-source/README.md` are the
package's original release notes, preserved unchanged.

## Study dataset

`study/study-paper-data.xlsx` is the dataset behind the paper's empirical study.
It has one vulnerability per row (97 records) and a `Field guide` sheet defining
every column. It is a derived, paper-facing extract: evidence, parameter details,
and the underlying per-record raw JSON are not included, and gate annotations are
represented as counts. `FILES.txt`, `SHA256SUMS`, and `SOURCE-MANIFEST.json` under
`actionwire-source/` describe the source tree only; they do not cover this file.

This companion guide does not change the source tree. Versioned implementation
files such as `v8.py`, `v14.py`, and `v15.py` remain because the current code
imports them. Do not remove files based solely on version numbers. Some retained
research documents link to excluded datasets or mention original-machine paths;
use the input requirements and explicit path options described above.
