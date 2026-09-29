"""Execute forced mock-provider adapter qualification with structured evidence."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Protocol

from src.projects import get_project

from .campaign_contracts import canonical_json, digest
from .contracts import ValidationError, atomic_write_json, atomic_write_text, redact_text, sha256_file
from .source_revision_compatibility import binding_hash_matches
from .qualification_containers import ContainerBinding, OciContainer
from .qualification_contracts import (
    FORCED_PATH_OUTCOMES,
    LIVE_TRIGGERABILITY_OUTCOMES,
    QUALIFICATION_EVENT_SCHEMA_VERSION,
    QUALIFICATION_RESULT_SCHEMA_VERSION,
    QUALIFICATION_STATUSES,
    QualificationRun,
    QualificationRunRequest,
    canonical_jsonl,
    validate_qualification_event,
    validate_qualification_case,
)
from .qualification_provider import (
    PROVIDER_MODEL,
    PROVIDER_SCHEMA_VERSION,
    MockProviderCall,
    transcript_record,
    validate_provider_exchange,
    write_provider_transcript,
)
from .qualification_images import prepare_qualification_containers


class QualificationRuntime(Protocol):
    def preflight(self, case: Mapping[str, Any]) -> tuple[bool, str, Mapping[str, Any]]: ...

    def run_pair(
        self, case: Mapping[str, Any], attempt: int
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]]: ...

    def close(self) -> None: ...


class OciQualificationRuntime:
    """Invoke only a labelled, in-container native-dispatch bridge."""

    def __init__(self, engine: str, campaign_dir: Path) -> None:
        self.engine = resolve_oci_engine(engine)
        self.campaign_id = str(_read_json(campaign_dir / "campaign.json").get("campaign_id", ""))
        bindings_path = campaign_dir / "containers" / "image-bindings.json"
        try:
            self.image_bindings = _read_json(bindings_path)
        except (OSError, json.JSONDecodeError):
            self.image_bindings = {}
        self._containers: dict[str, tuple[OciContainer, ContainerBinding, Mapping[str, Any]]] = {}

    @staticmethod
    def _key(case: Mapping[str, Any]) -> tuple[str, str, str]:
        family = case["family"]
        return (
            str(family["project"]),
            str(family["adapter"]),
            str(case["revision"]),
        )

    def preflight(self, case: Mapping[str, Any]) -> tuple[bool, str, Mapping[str, Any]]:
        project = str(case["family"]["project"])
        key = self._key(case)
        if key in self._containers:
            _, _, binding = self._containers[key]
            return True, "reused healthy OCI baseline", binding
        record = self.image_bindings.get(project)
        if not isinstance(record, Mapping):
            return False, f"no rendered OCI image binding for {project}", {}
        if (
            record.get("adapter") != case["family"]["adapter"]
            or record.get("revision") != case["revision"]
        ):
            return False, "project OCI binding does not match the qualification family", {}
        container = OciContainer(self.engine, case, record)
        ready, reason, binding = container.preflight()
        if not ready or binding is None:
            return False, reason, {}
        try:
            runtime_binding = container.start(binding)
        except Exception as exc:
            return False, f"OCI baseline start failed: {type(exc).__name__}: {exc}", {}
        self._containers[key] = (container, binding, runtime_binding)
        return True, "OCI baseline started", runtime_binding

    def _destroy(self, key: str) -> None:
        entry = self._containers.pop(key, None)
        if entry is not None:
            entry[0].stop()

    def run_pair(
        self, case: Mapping[str, Any], attempt: int
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        import subprocess

        key = self._key(case)
        container, image_binding, runtime_binding = self._containers[key]
        pair_id = f"{case['case_id']}:{attempt:03d}"
        request = {
            "schema_version": "clawgap-qualification-bridge/v1",
            "campaign_id": self.campaign_id,
            "case": case,
            "case_id": case["case_id"],
            "attempt": attempt,
            "pair_id": pair_id,
        }
        try:
            completed = subprocess.run(
                [
                    self.engine,
                    "exec",
                    "-i",
                    container.name,
                    image_binding.python,
                    "-m",
                    "src.runtime_validation.qualification_bridge",
                ],
                input=json.dumps(request, ensure_ascii=False, sort_keys=True),
                capture_output=True,
                text=True,
                timeout=240,
                check=False,
            )
            if completed.returncode != 0:
                raise ValidationError(
                    f"in-container dispatch bridge failed: {redact_text(completed.stderr[-1200:])}"
                )
            try:
                bridge_result = json.loads(completed.stdout)
            except json.JSONDecodeError as exc:
                raise ValidationError(f"in-container bridge returned invalid JSON: {exc}") from exc
            if (
                bridge_result.get("case_id") != case["case_id"]
                or bridge_result.get("attempt") != attempt
                or bridge_result.get("pair_id") != pair_id
                or bridge_result.get("campaign_id") != self.campaign_id
            ):
                raise ValidationError("in-container bridge identity mismatch")
            reset = container.reset(pair_id)
            return bridge_result, {
                **runtime_binding,
                **reset,
                "bridge_stderr": redact_text(completed.stderr[-2000:]),
            }
        except Exception:
            self._destroy(key)
            raise

    def close(self) -> None:
        for key in list(self._containers):
            self._destroy(key)


def resolve_oci_engine(engine: str) -> str:
    if engine in {"docker", "podman"}:
        return engine
    if engine == "auto":
        if shutil.which("podman"):
            return "podman"
        if shutil.which("docker"):
            return "docker"
        raise ValidationError("no supported OCI engine is available")
    raise ValidationError("qualification engine must be docker, podman, or auto")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValidationError(f"expected object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValidationError(f"{path}:{number}: expected object")
        rows.append(value)
    return rows


def _value(case: Mapping[str, Any], side: str) -> Any:
    source = case["native_case"].get("fixture_state") if case["native_case"]["matcher"].get("source") == "fixture-state" else case["replay"]
    current: Any = source[side] if source is not case["replay"] else source[f"{side}_args"]
    for item in case["native_case"]["matcher"]["path"]:
        if not isinstance(current, Mapping):
            return None
        current = current.get(item)
    return current


def _verify_bindings(case: Mapping[str, Any]) -> None:
    spec = get_project(case["family"]["project"])
    if spec.analysis_revision != case["revision"]:
        raise ValidationError("qualification revision drift")
    for section in ("source_binding", "dependency_binding"):
        for binding in case[section].get("files", []):
            relative = Path(binding["path"])
            path = Path(__file__).resolve().parents[2] / relative
            if not relative.is_absolute() and not str(relative).startswith("benchmark/"):
                path = spec.source_root / relative
            actual = sha256_file(path) if path.is_file() else ""
            if not path.is_file() or not binding_hash_matches(
                project=case["family"]["project"],
                relative=str(binding["path"]),
                expected=str(binding["sha256"]),
                actual=actual,
                source_root=spec.source_root,
            ):
                raise ValidationError(f"qualification {section} drift: {binding['path']}")


_UNSPECIFIED = object()


def _event(
    *,
    campaign_id: str,
    case: Mapping[str, Any],
    attempt: int,
    side: str,
    sequence: int,
    stage: str,
    relation: str,
    details: Mapping[str, Any],
    value: Any = _UNSPECIFIED,
) -> dict[str, Any]:
    if value is _UNSPECIFIED:
        value = _value(case, side)
    correlation = f"{campaign_id}:{case['case_id']}:{attempt}:{side}"
    event = {
        "schema_version": QUALIFICATION_EVENT_SCHEMA_VERSION,
        "sequence": sequence,
        "campaign_id": campaign_id,
        "case_id": case["case_id"],
        "pair_id": f"{case['case_id']}:{attempt}",
        "attempt": attempt,
        "side": side,
        "correlation_id": correlation,
        "source_binding_sha256": digest(case["source_binding"]),
        "value_id": "RVQV-" + digest(value)[:16],
        "stage": stage,
        "relation": relation,
        "details": {"value": value, **details},
    }
    event["event_id"] = "RVQE-" + digest(event)[:32]
    return validate_qualification_event(event)


def _side_events(
    campaign_id: str,
    case: Mapping[str, Any],
    attempt: int,
    side: str,
    result: Mapping[str, Any],
    provider_row: Mapping[str, Any],
) -> list[dict[str, Any]]:
    provider_request = provider_row.get("request", {})
    provider_response = provider_row.get("response", {})
    common = {
        "campaign_id": campaign_id,
        "case": case,
        "attempt": attempt,
        "side": side,
    }
    events = [
        _event(
            **common,
            sequence=1,
            stage="prompt_ingress",
            relation="equals",
            value=case["prompt"],
            details={"prompt": case["prompt"], "prompt_sha256": digest(case["prompt"])},
        ),
        _event(
            **common,
            sequence=2,
            stage="provider_request",
            relation="equals",
            value=provider_request,
            details={
                "protocol": "openai-chat-completions/loopback",
                "model": provider_row.get("model"),
                "request": provider_request,
                "request_sha256": provider_row.get("request_sha256"),
            },
        ),
        _event(
            **common,
            sequence=3,
            stage="provider_tool_call",
            relation="json-subset",
            value=provider_response,
            details={
                "protocol": case["mock_provider"]["protocol"],
                "tool_call": case["mock_provider"]["tool_calls"][side],
                "response": provider_response,
                "response_sha256": provider_row.get("response_sha256"),
            },
        ),
        _event(
            **common,
            sequence=4,
            stage="native_dispatch",
            relation="equals",
            value=case["replay"]["tool_name"],
            details={"tool_name": case["replay"]["tool_name"]},
        ),
    ]
    if side == "control":
        for observation in case["observations"]:
            if observation["kind"] == "handler" and result.get("handler_reached") is True:
                events.append(
                    _event(
                        **common,
                        sequence=5,
                        stage=f"source:{observation['stage_id']}",
                        relation="source-bound",
                        details={
                            "stage_id": observation["stage_id"],
                            "kind": observation["kind"],
                            "file": observation["file"],
                            "line": observation["line"],
                        },
                    )
                )
            if observation["kind"] == "gate" and result.get("gate_observed") is True:
                events.append(
                    _event(
                        **common,
                        sequence=6,
                        stage=f"source:{observation['stage_id']}",
                        relation="source-bound",
                        details={
                            "stage_id": observation["stage_id"],
                            "kind": observation["kind"],
                            "file": observation["file"],
                            "line": observation["line"],
                        },
                    )
                )
                break
    observed = set(result.get("observed_stages", []))
    sequence = len(events)
    for observation in case["observations"]:
        if observation["stage_id"] not in observed:
            continue
        sequence += 1
        stage = "effect_intercepted" if observation["kind"] == "effect" else f"source:{observation['stage_id']}"
        events.append(_event(campaign_id=campaign_id, case=case, attempt=attempt, side=side, sequence=sequence, stage=stage, relation="source-bound", details={"stage_id": observation["stage_id"], "kind": observation["kind"], "file": observation["file"], "line": observation["line"]}))
    return events


def _pair_passes(
    case: Mapping[str, Any],
    pair: Mapping[str, Any],
    reset: Mapping[str, Any],
) -> tuple[bool, str]:
    exploit = pair.get("exploit", {})
    control = pair.get("control", {})
    required = [row["stage_id"] for row in case["observations"]]
    if exploit.get("verdict") != "triggered" or not exploit.get("healthy"):
        return False, "exploit did not reach the intercepted source-bound effect"
    if exploit.get("observed_stages") != required:
        return False, "exploit source stages are incomplete or out of order"
    if not control.get("healthy") or control.get("unsafe_matched") is True:
        return False, "control did not preserve the safe outcome"
    if reset.get("reset") != "passed":
        return False, "deterministic reusable-container reset failed"
    return True, "forced mock-provider path observed"


def _fallback_provider_rows(
    case: Mapping[str, Any], attempt: int
) -> list[dict[str, Any]]:
    rows = [
        {
            **transcript_record(
                MockProviderCall(
                    side=side,
                    prompt=case["prompt"],
                    model=PROVIDER_MODEL,
                    tool_name=case["replay"]["tool_name"],
                    arguments=case["replay"][f"{side}_args"],
                ),
                {
                    "model": PROVIDER_MODEL,
                    "messages": [{"role": "user", "content": case["prompt"]}],
                },
                {
                    "id": "not-executed",
                    "model": PROVIDER_MODEL,
                    "choices": [
                        {
                            "index": 0,
                            "finish_reason": "tool_calls",
                            "message": {
                                "role": "assistant",
                                "tool_calls": [
                                    {
                                        "id": "not-executed",
                                        "type": "function",
                                        "function": {
                                            "name": case["replay"]["tool_name"],
                                            "arguments": canonical_json(
                                                case["replay"][f"{side}_args"]
                                            ),
                                        },
                                    }
                                ],
                            },
                        }
                    ],
                },
                0,
            ),
            "attempt": attempt,
            "transport": "not-executed-fake-runtime",
        }
        for side in ("exploit", "control")
    ]
    return rows


def _validated_provider_rows(
    case: Mapping[str, Any],
    attempt: int,
    bridge_result: Mapping[str, Any],
) -> list[dict[str, Any]]:
    supplied = bridge_result.get("provider_transcript")
    if not isinstance(supplied, list):
        return _fallback_provider_rows(case, attempt)
    rows = [row for row in supplied if isinstance(row, Mapping)]
    if len(rows) != 2 or {row.get("side") for row in rows} != {"exploit", "control"}:
        raise ValidationError("mock-provider transcript is incomplete")
    for row in rows:
        side = str(row.get("side"))
        expected = case["mock_provider"]["tool_calls"].get(side)
        if row.get("schema_version") != PROVIDER_SCHEMA_VERSION or expected is None:
            raise ValidationError("mock-provider transcript schema mismatch")
        request = row.get("request")
        response = row.get("response")
        if not isinstance(request, Mapping) or not isinstance(response, Mapping):
            raise ValidationError("mock-provider transcript lacks HTTP exchange")
        validate_provider_exchange(
            case["prompt"],
            PROVIDER_MODEL,
            expected["name"],
            expected["arguments"],
            request,
            response,
        )
        if row.get("request_sha256") != digest(request) or row.get("response_sha256") != digest(response):
            raise ValidationError("mock-provider transcript hash mismatch")
    return rows


def _case_result(
    campaign_id: str,
    case: Mapping[str, Any],
    runtime: QualificationRuntime,
    root: Path,
    attempts: int,
) -> dict[str, Any]:
    _verify_bindings(case)
    ready, reason, binding = runtime.preflight(case)
    result_root = root / "runs" / case["case_id"]
    result_root.mkdir(parents=True, exist_ok=True)
    if not ready:
        return {
            "schema_version": QUALIFICATION_RESULT_SCHEMA_VERSION,
            "campaign_id": campaign_id,
            "case_id": case["case_id"],
            "family": case["family"],
            "qualification": "blocked",
            "forced_path": "inconclusive",
            "live_triggerability": "not-run",
            "reason": reason,
            "container": dict(binding),
            "attempts": [],
        }
    pairs = []
    for attempt in range(1, attempts + 1):
        attempt_root = result_root / f"attempt-{attempt:03d}"
        attempt_root.mkdir(parents=True, exist_ok=True)
        bridge_result, reset = runtime.run_pair(case, attempt)
        native_pair = (
            bridge_result["pair"]
            if isinstance(bridge_result.get("pair"), Mapping)
            else bridge_result
        )
        provider_rows = _validated_provider_rows(case, attempt, bridge_result)
        passed, pair_reason = _pair_passes(case, native_pair, reset)
        write_provider_transcript(
            attempt_root / "provider-transcript.jsonl", provider_rows
        )
        provider_by_side = {str(row["side"]): row for row in provider_rows}
        events = _side_events(
            campaign_id,
            case,
            attempt,
            "exploit",
            native_pair["exploit"],
            provider_by_side["exploit"],
        )
        events += _side_events(
            campaign_id,
            case,
            attempt,
            "control",
            native_pair["control"],
            provider_by_side["control"],
        )
        atomic_write_text(attempt_root / "events.jsonl", canonical_jsonl(events))
        atomic_write_json(
            attempt_root / "pair.json",
            {
                "pair": native_pair,
                "bridge": dict(bridge_result),
                "reset": reset,
                "passed": passed,
                "reason": pair_reason,
            },
        )
        pairs.append({"attempt": attempt, "passed": passed, "reason": pair_reason, "reset": reset})
    confirmed = len(pairs) == attempts and all(row["passed"] for row in pairs)
    return {
        "schema_version": QUALIFICATION_RESULT_SCHEMA_VERSION,
        "campaign_id": campaign_id,
        "case_id": case["case_id"],
        "family": case["family"],
        "qualification": "qualified" if confirmed else "inconclusive",
        "forced_path": "confirmed" if confirmed else "inconclusive",
        "live_triggerability": "not-run",
        "reason": "all paired forced paths passed" if confirmed else "one or more paired forced paths failed",
        "container": dict(binding),
        "attempts": pairs,
    }


def run_adapter_qualification(
    request: QualificationRunRequest,
    *,
    runtime: QualificationRuntime | None = None,
) -> QualificationRun:
    root = request.campaign_dir.resolve()
    campaign = _read_json(root / "campaign.json")
    cases = [validate_qualification_case(row) for row in _read_jsonl(root / "cases.jsonl")]
    target = campaign.get("target", {})
    expected_families = int(target.get("families", 0))
    expected_cases = int(target.get("cases", target.get("families", 0)))
    if (
        len(cases) != expected_cases
        or len({tuple(case["selection"]["family_key"]) for case in cases}) != expected_families
    ):
        raise ValidationError(
            "qualification campaign denominator drift: expected "
            f"{expected_cases} cases across {expected_families} families"
        )
    active_runtime = runtime or OciQualificationRuntime(request.engine, root)
    results = []
    try:
        for case in cases:
            try:
                result = _case_result(campaign["campaign_id"], case, active_runtime, root, request.attempts)
            except Exception as exc:
                result = {
                    "schema_version": QUALIFICATION_RESULT_SCHEMA_VERSION,
                    "campaign_id": campaign["campaign_id"],
                    "case_id": case["case_id"],
                    "family": case["family"],
                    "qualification": "inconclusive",
                    "forced_path": "inconclusive",
                    "live_triggerability": "not-run",
                    "reason": f"{type(exc).__name__}: {exc}",
                    "container": {},
                    "attempts": [],
                }
            results.append(result)
            atomic_write_json(root / "runs" / case["case_id"] / "result.json", result)
    finally:
        active_runtime.close()
    result_ids = [row["case_id"] for row in results]
    if sorted(result_ids) != sorted(case["case_id"] for case in cases):
        raise ValidationError("qualification results do not partition selected families")
    counts = Counter(row["qualification"] for row in results)
    forced = Counter(row["forced_path"] for row in results)
    live = Counter(row["live_triggerability"] for row in results)
    if set(counts) - QUALIFICATION_STATUSES or set(forced) - FORCED_PATH_OUTCOMES or set(live) - LIVE_TRIGGERABILITY_OUTCOMES:
        raise ValidationError("qualification results contain an unsupported disposition")
    atomic_write_text(root / "qualification-results.jsonl", canonical_jsonl(results))
    command = (
        "python -m src.runtime_validation run-adapter-qualification "
        f"--campaign {request.campaign_dir} --attempts {request.attempts} --engine {request.engine}"
    )
    summary = "\n".join(
        [
            "# Containerized Adapter Qualification",
            "",
            f"> Complete reproduction command: `{command}`",
            "",
            f"Cases: **{len(results)}**; families: **{expected_families}**; qualified: **{counts.get('qualified', 0)}**; blocked: **{counts.get('blocked', 0)}**; inconclusive: **{counts.get('inconclusive', 0)}**.",
            "",
            "This campaign validates mock-provider-to-native-dispatch observation infrastructure only. It does not issue a vulnerability verdict or adjudicate missing-check/wrong-check semantics.",
            "",
        ]
    )
    atomic_write_text(root / "qualification-summary.md", summary)
    atomic_write_json(root / "qualification-manifest.json", {"schema_version": "clawgap-runtime-qualification-manifest/v1", "campaign_id": campaign["campaign_id"], "reproduction_command": command, "denominators": {"cases": len(results), "families": expected_families}, "counts": {"qualification": dict(sorted(counts.items())), "forced_path": dict(sorted(forced.items())), "live_triggerability": dict(sorted(live.items()))}})
    return QualificationRun(campaign["campaign_id"], dict(counts), dict(forced), dict(live), root, tuple(results))


def _prepare_hermes_smoke(
    source_campaign: Path, staging: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    source_root = source_campaign.resolve()
    campaign = _read_json(source_root / "campaign.json")
    cases = [
        validate_qualification_case(row)
        for row in _read_jsonl(source_root / "cases.jsonl")
    ]
    selected = [
        case
        for case in cases
        if case["family"]["project"] == "hermes-agent"
        and case["family"]["tool_name"] == "read_file"
        and case["family"]["probe"] == "filesystem"
    ]
    if len(selected) != 1:
        raise ValidationError("Hermes read_file/filesystem smoke family is not unique")
    case = selected[0]
    smoke_id = "RVQSMOKE-" + digest(
        {"source_campaign": campaign.get("campaign_id"), "case_id": case["case_id"]}
    )[:16]
    smoke_campaign = {
        "schema_version": campaign["schema_version"],
        "campaign_id": smoke_id,
        "purpose": "hermes-mock-provider-smoke-only",
        "source_campaign": {
            "path": str(source_root),
            "campaign_id": campaign.get("campaign_id"),
        },
        "target": {"families": 1, "case_ids": [case["case_id"]]},
        "selection_rule": "source-campaign-selected-family",
        "provider": "deterministic-loopback-mock",
        "live_triggerability": "not-run",
    }
    atomic_write_json(staging / "campaign.json", smoke_campaign)
    atomic_write_text(staging / "cases.jsonl", canonical_jsonl([case]))
    ledger_path = source_root / "selection-ledger.jsonl"
    if ledger_path.is_file():
        family = case["selection"]["family_key"]
        rows = [
            row
            for row in _read_jsonl(ledger_path)
            if row.get("family") == family
        ]
        atomic_write_text(staging / "selection-ledger.jsonl", canonical_jsonl(rows))
    return smoke_campaign, case


def _copy_project_container_bindings(source_campaign: Path, staging: Path, engine: str) -> None:
    """Reuse the full pre-analysis per-project union binding for the smoke."""

    source_root = source_campaign.resolve()
    source_containers = source_root / "containers"
    if not (source_containers / "manifest.json").is_file():
        prepare_qualification_containers(source_root, engine)
    manifest = _read_json(source_containers / "manifest.json")
    manifest["campaign_dir"] = str(staging)
    manifest["engine"] = engine
    destination = staging / "containers"
    destination.mkdir(parents=True, exist_ok=True)
    atomic_write_json(destination / "manifest.json", manifest)
    atomic_write_json(destination / "image-bindings.json", manifest["bindings"])


def _rewrite_staging_paths(root: Path, staging: Path) -> None:
    for path in (
        root / "generation-manifest.json",
        root / "containers" / "image-builds.jsonl",
        root / "qualification-manifest.json",
    ):
        if not path.is_file():
            continue
        if path.suffix == ".jsonl":
            rows = [
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            value = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
        else:
            value = path.read_text(encoding="utf-8")
        value = value.replace(str(staging), str(root))
        atomic_write_text(path, value)


def run_hermes_qualification_smoke(
    campaign_dir: Path,
    out_dir: Path,
    *,
    engine: str = "auto",
    attempts: int = 3,
    build_image: bool = False,
    runtime: QualificationRuntime | None = None,
) -> QualificationRun:
    """Run the first real OCI family using only the deterministic mock provider."""

    if attempts != 3:
        raise ValidationError("Hermes qualification smoke requires exactly three pairs")
    if build_image:
        raise ValidationError("qualification containers must be built in pre-analysis, not during replay")
    resolved_engine = resolve_oci_engine(engine)
    out = out_dir.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{out.name}.staging-", dir=out.parent))
    backup = out.parent / f".{out.name}.backup-{os.getpid()}"
    try:
        smoke_campaign, case = _prepare_hermes_smoke(campaign_dir, staging)
        _copy_project_container_bindings(campaign_dir, staging, resolved_engine)
        active_runtime = runtime or OciQualificationRuntime(resolved_engine, staging)
        try:
            result = _case_result(
                smoke_campaign["campaign_id"], case, active_runtime, staging, attempts
            )
        finally:
            active_runtime.close()
        atomic_write_json(
            staging / "runs" / case["case_id"] / "result.json", result
        )
        counts = Counter([result["qualification"]])
        forced = Counter([result["forced_path"]])
        live = Counter([result["live_triggerability"]])
        atomic_write_text(staging / "qualification-results.jsonl", canonical_jsonl([result]))
        command = (
            "python -m src.runtime_validation run-hermes-qualification-smoke "
            f"--campaign {campaign_dir} --out-dir {out_dir} --engine {engine} --attempts {attempts}"
        )
        atomic_write_text(
            staging / "qualification-summary.md",
            "\n".join(
                [
                    "# Hermes Mock-Provider Qualification Smoke",
                    "",
                    f"> Complete reproduction command: `{command}`",
                    "",
                    f"Qualification: **{result['qualification']}**; forced path: **{result['forced_path']}**; live triggerability: **{result['live_triggerability']}**.",
                    "",
                    "This smoke qualifies only the Hermes prompt/mock-provider/native-dispatch observation path. It is not a vulnerability verdict.",
                    "",
                ]
            ),
        )
        atomic_write_json(
            staging / "qualification-manifest.json",
            {
                "schema_version": "clawgap-runtime-qualification-manifest/v1",
                "campaign_id": smoke_campaign["campaign_id"],
                "purpose": "hermes-mock-provider-smoke-only",
                "provider": "deterministic-loopback-mock",
                "reproduction_command": command,
                "counts": {
                    "qualification": dict(sorted(counts.items())),
                    "forced_path": dict(sorted(forced.items())),
                    "live_triggerability": dict(sorted(live.items())),
                },
            },
        )
        if backup.exists():
            raise ValidationError(f"stale Hermes smoke backup blocks publication: {backup}")
        if out.exists():
            os.replace(out, backup)
        os.replace(staging, out)
        if backup.exists():
            shutil.rmtree(backup)
        _rewrite_staging_paths(out, staging)
        return QualificationRun(
            smoke_campaign["campaign_id"],
            dict(counts),
            dict(forced),
            dict(live),
            out,
            (result,),
        )
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        if backup.exists() and not out.exists():
            os.replace(backup, out)
        raise


def run_exploratory_triggerability(campaign_dir: Path) -> list[dict[str, Any]]:
    """Publish explicit noncanonical placeholders until a live prompt adapter is configured."""

    root = campaign_dir.resolve()
    campaign = _read_json(root / "campaign.json")
    cases = [validate_qualification_case(row) for row in _read_jsonl(root / "cases.jsonl")]
    rows = [
        {
            "schema_version": "clawgap-runtime-live-triggerability/v1",
            "campaign_id": campaign["campaign_id"],
            "case_id": case["case_id"],
            "outcome": "not-run",
            "reason": "no project-specific live prompt adapter is configured",
        }
        for case in cases
    ]
    atomic_write_text(root / "live-triggerability.jsonl", canonical_jsonl(rows))
    return rows
