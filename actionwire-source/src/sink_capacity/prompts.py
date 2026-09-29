"""Prompt builders for the sink-API capability card (English, capability-only)."""
from __future__ import annotations

import json

from .doc_sources import DOC_URLS, SECURITY_REFS

SYSTEM = """\
You are a security capability analyst. For ONE sink API you produce a *capability \
description card* that fully and precisely describes WHAT THE API CAN DO when an \
attacker controls its security-relevant parameter(s).

OUTPUT CONTRACT (critical):
- You are producing TEXT, not doing a task. Your ENTIRE final reply MUST be the card \
itself — a Markdown document that starts with `# <api>`. No preamble, no trailing \
summary, no explanation of what you did, no "I wrote the card to ...".
- Do NOT create, write, or edit any file. The Read/Grep/Glob tools are ONLY for \
inspecting implementation source when needed; never write output to disk.

Hard rules:
- This is a CAPABILITY description, NOT a security review. Describe capabilities as \
FACTS ("the API can ...", "by default it ...").
- Do NOT mention gates, checks, validation, allowlists, "should", "must", mitigation, \
or how to fix anything. Whether a checkpoint covers this capability is a SEPARATE, \
LATER step. Never write obligations.
- Enumerate sub-capabilities exhaustively (e.g. for SSRF: internal-ip, cloud-metadata, \
DNS-rebinding/TOCTOU, redirect-following, non-http schemes, arbitrary port). Being \
granular matters more than being brief.
- Call out IMPLICIT/DEFAULT behaviors that silently widen capability (inherited env/cwd, \
redirect-following, symlink-following, DNS-resolved-at-connect, etc.).
- Ground every claim: prefer the provided signature/docstring and source; for well-known \
extreme capabilities cite the security references given.
- Output ENGLISH only.
- A user-consent sink is itself a security decision boundary. When the sink presents or \
forwards a model-controlled command for approval and returns the user's decision, stop at \
that boundary; do not reclassify the card as process execution merely because an approved \
command may execute later.
- For a source-owned dangerous-command approval sink whose surrounding source declares an \
approval-bypass policy, add the optional `policy_contract` block described below. This is \
the only allowed normative block. Do not add `policy_contract` to other capability classes.
- The ordinary card always has `normative_authority: capability-facts-only`; even a dangerous
  capability is not itself a mandatory security policy.
- Distinguish an API's possible roles from what a caller can actually bind. Every role has
  exact binding expressions and a `caller_bindable` boolean. Do not mark internal/provider/
  library-derived state as caller-bindable.
- Put conditional effects in separate facets with explicit activation predicates. Do not
  describe a shell-only, redirect-only, or optional-argument capability as unconditional.
- Record restrictions guaranteed by the concrete library/runtime in `library_guarantees`,
  and defaults in `defaults`. Never claim a protocol/scheme the default library cannot send.

Output format — a Markdown document, and nothing else:
1) An H1 title line: `# <api>`
2) One fenced ```yaml block containing exactly these keys:
   schema_version, card_id, api, api_family, runtime, capability_class,
   normative_authority, bound_sinks, roles, facets, library_guarantees, defaults,
   example_usage, provenance, and optionally policy_contract.
`runtime` has exactly language/ecosystem/package/version. `roles` contains role_id,
description, and bindings; every binding has expression and caller_bindable. `facets` contains
facet_id, capability, role_ids, and activation. `library_guarantees` contains guarantee_id,
statement, and activation. `defaults` contains default_id, role_id (or null), value,
security_effect, and activation.
Every activation contains all_of and/or any_of predicates. A predicate has exactly
predicate/subject/operator/value. Allowed predicates: always, role-bound,
role-caller-bindable, role-authority, role-value, runtime-feature, transform-present,
call-shape, default-active. Allowed operators: equals, not-equals, contains, in, exists.
Keep example_usage code minimal and runnable; `capability_edge` shows the API pushed to \
its capability limit (these double as PoC seeds).

Optional approval policy format:
policy_contract:
  schema_version: approval-policy-contract/v1
  boundary: dangerous-command-user-consent
  requirements:
    - policy_id: <lowercase semantic slug>
      rule: <project-neutral mandatory policy>
      applicability: <when the policy applies>
      security_effect: <effect prevented by enforcing the policy>
      examples: [<one or more concrete command examples>]
For shell-command approval bypasses, reason about effective command semantics rather than \
only the shell name: indirect operands, variable/glob expansion, effect-changing redirection, \
and execution/mutation action flags are distinct policy facets.
"""


def build_user(
    sink,
    doc: dict | None,
    source: dict | None,
    web_doc: str | None = None,
    source_roots: list[str] | None = None,
    card_identity: dict | None = None,
    preserved_policy_contract: dict | None = None,
) -> str:
    parts: list[str] = []
    parts.append(f"SINK API: {sink.api}")
    parts.append(f"capability_class (suggested): {sink.capability_class}")
    parts.append(f"kind: {sink.kind}")
    parts.append(f"How it is matched in CodeQL (is_sink_af disjunct): {sink.match}")
    parts.append(
        "This sink is reached from LLM-driven tool calls in the hermes-agent project; "
        "the model controls the parameter noted below."
    )
    if card_identity:
        parts.append(
            "\n--- REQUIRED V2 IDENTITY (copy byte-for-byte) ---\n"
            + json.dumps(card_identity, indent=2, ensure_ascii=False)
        )
    if preserved_policy_contract:
        parts.append(
            "\n--- SOURCE-OWNED POLICY CONTRACT (copy exactly; do not add, remove, "
            "merge, or rewrite requirements) ---\n"
            + json.dumps(preserved_policy_contract, indent=2, ensure_ascii=False)
        )

    if doc:
        parts.append("\n--- INSTALLED-PACKAGE INTROSPECTION (authoritative, version-pinned) ---")
        if doc.get("version"):
            parts.append(f"version: {doc['version']}")
        if doc.get("signature"):
            parts.append(f"signature: {doc['signature']}")
        if doc.get("doc"):
            parts.append("docstring:\n" + doc["doc"])
        if doc.get("error"):
            parts.append(f"(introspection note: {doc['error']})")
    if web_doc:
        parts.append(
            "\n--- OFFICIAL DOC EXCERPT (locally cached snapshot; authoritative narrative) ---\n"
            + web_doc.strip()
        )

    if sink.kind == "project":
        loc = f"{source['file']}:{source['line']}" if source else None
        roots = ", ".join(source_roots) if source_roots else "the hermes-agent source tree"
        parts.append(
            "\n--- PROJECT-INTERNAL IMPLEMENTATION — READ IT YOURSELF (use the Read/Grep tools) ---"
        )
        if loc:
            parts.append(f"The implementation is at {loc}.")
        else:
            parts.append(
                f"Locate the definition (`def {sink.api.split('.')[-1].split(' ')[0]}` or the "
                f"receiver's method) under {roots} with Grep, then open it."
            )
        parts.append(
            "READ the actual function body, and FOLLOW what it delegates to — a wrapper often "
            "bottoms out at a real primitive (e.g. subprocess.Popen / open / an HTTP client / a "
            "WebSocket send). Trace down to that real primitive and base the capability on what "
            "the code ACTUALLY does (not on the wrapper's name). Cite the file:line you read in "
            "`provenance`."
        )

    if sink.import_path and sink.import_path in DOC_URLS:
        parts.append(f"\nCanonical doc URL (for provenance): {DOC_URLS[sink.import_path]}")
    refs = SECURITY_REFS.get(sink.capability_class)
    if refs:
        parts.append("Security references (for provenance / extreme-capability enumeration): "
                     + "; ".join(refs))

    parts.append(
        "\nWrite the capability card now. Remember: capability facts + runnable examples "
        "only; no gates, no obligations outside the supplied source-owned policy_contract."
    )
    return "\n".join(parts)
