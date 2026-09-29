"""Apply reviewed, hash-bound model-origin gate qualification to an input view.

This validates a reviewed qualification, not automatic taint inference. Raw upstream
artifacts remain unchanged; all original members stay in the selected groups.
"""

from copy import deepcopy
from dataclasses import replace
import json

from .contracts import GroupOracleError, canonical_json, digest, sha256_file


def _pointer(value, path):
    if not isinstance(path, str) or not path.startswith("/"):
        raise GroupOracleError("qualification evidence requires a JSON pointer")
    try:
        for key in path.split("/")[1:]:
            key = key.replace("~1", "/").replace("~0", "~")
            value = value[int(key)] if isinstance(value, list) else value[key]
    except (KeyError, IndexError, ValueError, TypeError) as exc:
        raise GroupOracleError(f"invalid qualification evidence pointer: {path}") from exc
    return value


def qualify_inputs(inputs, path):
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GroupOracleError("cannot read gate qualification") from exc
    if document.get("schema_version") != "reviewed-gate-qualification/v1":
        raise GroupOracleError("unsupported gate qualification")
    groups = {g["handler_sink_group_id"] for g in inputs.security_groups}
    if set(document.get("group_ids", [])) != groups:
        raise GroupOracleError("qualification must cover exactly the selected groups")
    records = document.get("chains", [])
    if not isinstance(records, list):
        raise GroupOracleError("qualification chains must be a list")
    by_key = {}
    for row in records:
        key = (row["project"], row["chain_id"])
        if key in by_key:
            raise GroupOracleError("duplicate qualification member")
        by_key[key] = row
    if set(by_key) != set(inputs.chains):
        raise GroupOracleError("qualification must cover every selected member")
    members, audit_members = {}, []
    for key, chain in sorted(inputs.chains.items()):
        row, original = by_key[key], chain.semantic_ir
        if row["revision"] != chain.revision or row["semantic_ir_sha256"] != digest(original):
            raise GroupOracleError(f"qualification semantic/revision drift: {chain.ref}")
        ids = row["qualified_gate_uids"]
        available = {g["gate_uid"] for g in original["gates"]}
        if not isinstance(ids, list) or len(ids) != len(set(ids)) or not set(ids) <= available:
            raise GroupOracleError("unknown or duplicate qualified gate")
        supported = set()
        for proof in row["model_origin_evidence"]:
            uid = proof["gate_uid"]
            if uid not in ids:
                raise GroupOracleError("origin evidence refers to an unqualified gate")
            value = _pointer(original, proof["input_locator"])
            if canonical_json(value) != canonical_json(proof["exact_value"]):
                raise GroupOracleError("model-origin qualification quote drift")
            supported.add(uid)
        if supported != set(ids):
            raise GroupOracleError("each qualified gate needs exact reviewed origin evidence")
        semantic = deepcopy(original)
        semantic["gates"] = [g for g in semantic["gates"] if g["gate_uid"] in ids]
        gate_ids = {g["semantic"]["gate_id"] for g in semantic["gates"]}
        for value in semantic.get("values", []):
            if "gate_bindings" in value:
                value["gate_bindings"] = [b for b in value["gate_bindings"] if b["gate_id"] in gate_ids]
        semantic["summary"] = (
            f"Reviewed model-origin gate view: {len(ids)} of {len(original['gates'])} "
            f"input gates admitted; original summary: {original.get('summary', '')}"
        )
        members[key] = replace(chain, semantic_ir=semantic)
        audit_members.append({"project": key[0], "chain_id": key[1], "revision": chain.revision,
                              "original_semantic_sha256": row["semantic_ir_sha256"],
                              "original_gate_count": len(original["gates"]),
                              "qualified_gate_uids": ids,
                              "excluded_gate_uids": sorted(available-set(ids))})
    audit = {"method": "reviewed-model-origin-qualification", "path": str(path),
             "sha256": sha256_file(path), "groups": sorted(groups), "members": audit_members,
             "automatic_taint_proof": False, "raw_inputs_modified": False}
    return replace(inputs, chains=members, digests={**inputs.digests, "gate_qualification": audit}), audit
