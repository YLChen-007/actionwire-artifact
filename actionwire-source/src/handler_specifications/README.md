# Shared Handler-Specification Extraction

This package statically derives the model-facing definition associated with every row in each registered project's `handler-entry/debug/tool-handler-entries.csv`. The CSV remains the authoritative handler universe; the extractor groups duplicate rows by `tool_name` and emits one canonical tool record without importing or executing benchmark modules.

Run from the repository root:

```bash
python -m src.handler_specifications --project <project-id>
python -m src.handler_specifications --all
```

Single-project mode accepts `--source-root`, `--handler-inventory`, `--revision`, and `--output-directory`. A source override requires an explicit revision. `--all` accepts no overrides: it resolves all 12 active projects from `src.projects`, builds and validates every inventory before writing the first artifact, and writes each file through an atomic replacement.

The canonical outputs are:

```text
<ProjectSpec.output_root>/handler-specifications/tool-handler-specifications.json
<ProjectSpec.output_root>/handler-specifications/tool-handler-specifications.md
```

The JSON schema identifier is `clawgap/tool-handler-specifications/v2`. It records the registered project identity and revision, complete repository-root reproduction command, handler-inventory and consumed-source SHA-256 hashes, aggregate counts, and one sorted record per unique tool. A resolved `function` contains exactly `name`, `description`, and `parameters`. Source- or configuration-dependent variants remain in `runtime_rules`; they do not create duplicate tools. Every Markdown artifact puts its complete reproduction command at the beginning of the report.

Python adapters use a restricted AST evaluator for registrations, decorators, class/dataclass metadata, properties, signatures, annotations, defaults, and docstrings. TypeScript adapters use the compiler API already vendored under `src/gate_semantics/lsp/node_modules/typescript`; they evaluate literal objects, local imports, TypeBox, Zod, MCP declarations, structured output, and wrapper provenance. LettaBot's pinned Letta Code handlers are joined statically with their `toolDefinitions.ts` bindings, JSON schemas, and Markdown descriptions. Unsupported calls or AST shapes fail closed with file and line evidence. Neither adapter imports benchmark code or installs/executes benchmark packages.

External runtime-owned interfaces have `function: null` and an explicit unresolved reason. The current source-confirmed set is eight tools: imported `read`/`write`/`edit` tools in each OpenClaw tree and the dynamic MCP wrappers in AstrBot and Nanobot. LettaBot's seven pinned client tools are resolved from vendored source; its two server-only boundaries are audited separately and are not handler rows. DroidClaw records use `structured-output-action`, not ordinary function-tool identity.

The revision-pinned acceptance baseline is 12 projects, 316 handler rows, 309 unique tools, 301 resolved specifications, and eight explicitly unresolved boundaries. Tests require a one-to-one match between registered source roots and the project directories under `benchmark/{python,typescript}`; they also lock Hermes's 67 definitions, duplicate grouping, traversal and unsafe-expression failures, schema/hash validation, deterministic rendering, all-project no-write-on-validation-failure, Markdown commands, and compatibility parity. LobsterAI, CodeG, and TinyClaw are retired from the active benchmark; their source snapshots, former outputs, and historical design material remain under `tmp/`, `tmp/retired-output/`, and `design/` respectively.

`design/hermes-agent/handler-entry/debug/script/generate_tool_handler_specifications.py` is a compatibility launcher and re-exports the focused Hermes evaluator API. Its default command writes the same v2 bytes as `python -m src.handler_specifications --project hermes-agent`; the former generated specifications under `design/hermes-agent/handler-entry/debug/` are retired.
