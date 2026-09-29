# Synthetic OpenClaw two-vulnerability fixture

This fixture is an intentionally vulnerable, minimal derivative used only to test
the TypeScript CodeQL model. It is not upstream OpenClaw `v2026.2.1` and must not be
included in revision-pinned coverage, paper metrics, or vulnerability-presence
claims.

The fixture combines two source shapes that never coexisted in the pinned release:

- `Advisory-GHSA-527m-976r-jf79-dataflow-wait-fn-existing-session`: a bundled
  `extensions/browser` handler whose controlled function text reaches Chrome MCP
  `client.callTool`;
- `Media_Root_Bypass-ISSUE-REPORT-fixed`: a message handler that normalizes only
  `media` while unchecked `mediaUrl`/`fileUrl` aliases reach a local `fs.open`.

Run from the repository root:

```bash
bin/codeql test run --threads=1 --additional-packs=src/ql-js -- \
  src/ql-js/tests/openclaw_two_vul_synthetic
```

To materialize the same paths in a full source-level derivative of the
`v2026.2.1` benchmark, run:

```bash
python scripts/build_openclaw_two_vul_synthetic.py
```

The generated source is written to
`benchmark/typescript/openclaw-v2026.2.1-two-vul-synthetic/` and contains a
`SYNTHETIC_DERIVATIVE.json` identity marker.
