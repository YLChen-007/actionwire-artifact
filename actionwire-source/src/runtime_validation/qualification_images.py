"""Prepare and build checked-in, revision-bound qualification containers."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping

from src.projects import get_project

from .campaign_contracts import digest
from .contracts import ValidationError, atomic_write_json, atomic_write_text, sha256_file
from .qualification_contracts import validate_qualification_case


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTAINER_DEFINITION_ROOT = Path(__file__).resolve().parent / "containers"
CONTAINER_MANIFEST_PATH = CONTAINER_DEFINITION_ROOT / "manifest.json"
BRIDGE_DEPENDENCIES = ("jsonschema==4.25.1",)
BRIDGE_DEPENDENCY_ID = ",".join(BRIDGE_DEPENDENCIES)


def _read_json_file(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid container input {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"container input must be an object: {path}")
    return value


def _read_cases(campaign: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    path = campaign / "cases.jsonl"
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"{path}:{number}: invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ValidationError(f"{path}:{number}: expected object")
        rows.append(validate_qualification_case(value))
    return rows


def _group_cases(cases: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        grouped[case["family"]["project"]].append(case)
    return dict(grouped)


def _union_binding(cases: list[dict[str, Any]], section: str) -> dict[str, Any]:
    files: dict[str, str] = {}
    for case in cases:
        for binding in case[section].get("files", []):
            path = str(binding["path"])
            expected = str(binding["sha256"])
            if path in files and files[path] != expected:
                raise ValidationError(f"conflicting {section} binding for {path}")
            files[path] = expected
    return {"files": [{"path": path, "sha256": files[path]} for path in sorted(files)]}


def _bridge_binding() -> dict[str, Any]:
    roots = (REPO_ROOT / "src" / "runtime_validation", REPO_ROOT / "src" / "projects")
    host_only = {
        "qualification_images.py",
        "qualification_selection.py",
        "qualification_runner.py",
        "qualification_containers.py",
        "__main__.py",
    }
    files: list[dict[str, str]] = []
    for root in roots:
        for path in sorted(root.rglob("*")):
            if (
                not path.is_file()
                or "__pycache__" in path.parts
                or "tests" in path.parts
                or path.name == "README.md"
                or path.parent == roots[0] and path.name in host_only
                or (path.suffix not in {".py", ".ts", ".json"} and path.name != "Dockerfile")
            ):
                continue
            files.append(
                {"path": str(path.relative_to(REPO_ROOT)), "sha256": sha256_file(path)}
            )
    init = REPO_ROOT / "src" / "__init__.py"
    if init.is_file():
        files.append({"path": "src/__init__.py", "sha256": sha256_file(init)})
    return {"files": sorted(files, key=lambda row: row["path"])}


def _container_definitions() -> dict[str, Any]:
    value = _read_json_file(CONTAINER_MANIFEST_PATH)
    if value.get("schema_version") != "clawgap-runtime-qualification-container-definitions/v1":
        raise ValidationError("unsupported qualification container definition schema")
    if value.get("build_phase") != "pre-analysis":
        raise ValidationError("qualification containers must be built in pre-analysis")
    projects = value.get("projects")
    if not isinstance(projects, dict):
        raise ValidationError("container definitions lack a project map")
    return value


def _definition_binding(definition: Mapping[str, Any]) -> dict[str, Any]:
    files = [{"path": "src/runtime_validation/containers/manifest.json",
              "sha256": sha256_file(CONTAINER_MANIFEST_PATH)}]
    dockerfile = definition.get("dockerfile")
    if dockerfile:
        path = CONTAINER_DEFINITION_ROOT / str(dockerfile)
        if not path.is_file():
            raise ValidationError(f"container Dockerfile is unavailable: {dockerfile}")
        files.append({
            "path": f"src/runtime_validation/containers/{dockerfile}",
            "sha256": sha256_file(path),
        })
    return {"files": files}


def _project_records(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    definitions = _container_definitions()["projects"]
    rows: list[dict[str, Any]] = []
    for project, project_cases in sorted(_group_cases(cases).items()):
        definition = definitions.get(project)
        if not isinstance(definition, Mapping):
            raise ValidationError(f"no checked-in container definition for {project}")
        revisions = {case["revision"] for case in project_cases}
        if len(revisions) != 1:
            raise ValidationError(f"qualification project {project} has multiple revisions")
        source_binding = _union_binding(project_cases, "source_binding")
        dependency_binding = _union_binding(project_cases, "dependency_binding")
        revision = next(iter(revisions))
        bridge_binding = _bridge_binding()
        definition_binding = _definition_binding(definition)
        bindings = {
            "revision": revision,
            "source_binding": source_binding,
            "dependency_binding": dependency_binding,
            "bridge_binding": bridge_binding,
            "definition_binding": definition_binding,
        }
        binding_digest = digest(bindings)
        normalized = project.lower().replace("_", "-")
        spec = get_project(project).resolved()
        declared_source = str(definition["source_root"])
        registry_source = str(spec.source_root.relative_to(REPO_ROOT))
        if declared_source != registry_source or not (REPO_ROOT / declared_source).is_dir():
            raise ValidationError(
                f"container source path for {project} is not the benchmark project path"
            )
        rows.append(
            {
                "project": project,
                "adapter": project_cases[0]["family"]["adapter"],
                "revision": revision,
                "source_root": declared_source,
                "source_binding": source_binding,
                "dependency_binding": dependency_binding,
                "source_digest": digest(source_binding),
                "dependency_digest": digest(dependency_binding),
                "bridge_digest": digest(bridge_binding),
                "bridge_binding": bridge_binding,
                "definition_digest": digest(definition_binding),
                "definition_binding": definition_binding,
                "binding_digest": binding_digest,
                "image": f"clawgap-qualification-{normalized}:{revision[:12]}-{binding_digest[:12]}",
                "buildable": bool(definition.get("buildable")),
                "smoke_first": bool(definition.get("smoke_first")),
                "definition": dict(definition),
                "definition_path": "src/runtime_validation/containers/manifest.json",
                "dockerfile_path": (
                    f"src/runtime_validation/containers/{definition['dockerfile']}"
                    if definition.get("dockerfile") else None
                ),
                "base_image": definition.get("base_image"),
                "bridge_dependencies": list(BRIDGE_DEPENDENCIES),
            }
        )
    expected = set(definitions)
    actual = {row["project"] for row in rows}
    if expected != actual:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValidationError(
            f"container definition denominator drift; missing={missing}, extra={extra}"
        )
    return rows


def _verify_host_bindings(record: Mapping[str, Any]) -> None:
    spec = get_project(str(record["project"])).resolved()
    for section in ("source_binding", "dependency_binding"):
        for binding in record[section]["files"]:
            path = Path(str(binding["path"]))
            if path.is_absolute():
                candidate = path
            elif path.parts and path.parts[0] == "benchmark":
                candidate = REPO_ROOT / path
            else:
                candidate = spec.source_root / path
            if not candidate.is_file() or sha256_file(candidate) != binding["sha256"]:
                raise ValidationError(
                    f"qualification image {section} drift before build: {binding['path']}"
                )


def _bindings(records: list[dict[str, Any]]) -> dict[str, Any]:
    keys = (
        "project", "adapter", "revision", "source_root", "source_binding",
        "dependency_binding", "source_digest", "dependency_digest", "binding_digest",
        "bridge_digest", "bridge_binding", "definition_digest", "definition_binding",
        "image", "buildable", "smoke_first", "dockerfile_path", "base_image",
        "bridge_dependencies",
    )
    return {row["project"]: {key: row[key] for key in keys} for row in records}


def prepare_qualification_containers(
    campaign_dir: Path, engine: str = "auto"
) -> dict[str, Any]:
    if engine not in {"docker", "podman", "auto"}:
        raise ValidationError("qualification container engine must be docker, podman, or auto")
    root = campaign_dir.resolve()
    records = _project_records(_read_cases(root))
    definitions = _container_definitions()
    output = root / "containers"
    output.mkdir(parents=True, exist_ok=True)
    smoke_order = list(definitions.get("smoke_order", []))
    rows = sorted(records, key=lambda row: (not row["smoke_first"], row["project"]))
    manifest = {
        "schema_version": "clawgap-runtime-qualification-containers/v1",
        "build_phase": "pre-analysis",
        "campaign_dir": str(root),
        "engine": engine,
        "definition_manifest": "src/runtime_validation/containers/manifest.json",
        "definition_manifest_sha256": sha256_file(CONTAINER_MANIFEST_PATH),
        "smoke_order": smoke_order,
        "projects": rows,
        "bindings": _bindings(records),
        "reproduction_command": (
            "python -m src.runtime_validation prebuild-qualification-containers "
            f"--campaign {campaign_dir} --engine {engine}"
        ),
        "note": (
            "Definitions are checked in under src/runtime_validation/containers. Hermes Agent is "
            "the first smoke target; unadmitted runtime bases remain explicitly blocked."
        ),
    }
    atomic_write_json(output / "manifest.json", manifest)
    atomic_write_json(output / "image-bindings.json", manifest["bindings"])
    return manifest


def render_qualification_image_recipes(
    campaign_dir: Path, engine: str = "auto"
) -> dict[str, Any]:
    """Compatibility alias for the pre-analysis container preparation stage."""

    return prepare_qualification_containers(campaign_dir, engine)


def _stage_build_context(record: Mapping[str, Any], context: Path) -> None:
    if context.exists():
        shutil.rmtree(context)
    context.mkdir(parents=True)
    ignore = shutil.ignore_patterns(
        ".git", ".venv", "venv", ".agentfuzz-main-venv", "node_modules",
        "__pycache__",
        ".pytest_cache", ".ruff_cache",
    )
    source = Path(str(record["source_root"]))
    if not source.parts or source.parts[0] != "benchmark":
        raise ValidationError("qualification build source must be a benchmark project path")
    (context / "src").mkdir()
    init = REPO_ROOT / "src" / "__init__.py"
    if init.is_file():
        shutil.copy2(init, context / "src" / "__init__.py")
    for binding in _bridge_binding()["files"]:
        bridge_source = REPO_ROOT / binding["path"]
        destination = context / binding["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(bridge_source, destination)
    (context / source.parent).mkdir(parents=True, exist_ok=True)
    shutil.copytree(REPO_ROOT / source, context / source, ignore=ignore)
    atomic_write_text(context / ".dockerignore", ".git\nnode_modules\n.venv\n__pycache__\n")


def _inspect_image(engine: str, image: str) -> dict[str, Any]:
    completed = subprocess.run(
        [engine, "image", "inspect", image, "--format", "{{json .}}"],
        capture_output=True, text=True, timeout=60, check=False,
    )
    if completed.returncode != 0:
        raise ValidationError(
            f"cannot inspect qualification image: {completed.stderr[-800:]}"
        )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid OCI inspect output: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError("OCI inspect output must be an object")
    return value


def _required_labels(record: Mapping[str, Any]) -> dict[str, str]:
    return {
        "org.clawgap.qualification.bridge": "v1",
        "org.clawgap.qualification.python": "python3",
        "org.clawgap.revision": str(record["revision"]),
        "org.clawgap.source-digest": str(record["source_digest"]),
        "org.clawgap.dependency-digest": str(record["dependency_digest"]),
        "org.clawgap.bridge-digest": str(record["bridge_digest"]),
        "org.clawgap.definition-digest": str(record["definition_digest"]),
        "org.clawgap.bridge-dependencies": BRIDGE_DEPENDENCY_ID,
    }


def _build_result(
    record: Mapping[str, Any],
    inspected: Mapping[str, Any],
    *,
    engine: str,
    campaign_dir: Path,
    build_context: str | None,
    build_log: str | None,
) -> dict[str, Any]:
    return {
        "schema_version": "clawgap-runtime-qualification-image-build/v1",
        "project": record["project"],
        "engine": engine,
        "image": record["image"],
        "image_id": str(inspected.get("Id", "")),
        "base_image": record.get("base_image"),
        "source_root": record["source_root"],
        "definition_manifest": record["definition_path"],
        "dockerfile": record.get("dockerfile_path"),
        "source_digest": record["source_digest"],
        "dependency_digest": record["dependency_digest"],
        "binding_digest": record["binding_digest"],
        "bridge_digest": record["bridge_digest"],
        "definition_digest": record["definition_digest"],
        "build_context": build_context,
        "build_log": build_log,
        "reproduction_command": (
            "python -m src.runtime_validation prebuild-qualification-containers "
            f"--campaign {campaign_dir} --project {record['project']} --engine {engine}"
        ),
    }


def _append_build(root: Path, result: Mapping[str, Any]) -> None:
    path = root / "containers" / "image-builds.jsonl"
    rows = []
    if path.is_file():
        rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    rows = [row for row in rows if row.get("project") != result["project"]]
    rows.append(dict(result))
    atomic_write_text(path, "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))


def build_qualification_image(
    campaign_dir: Path, project: str, engine: str = "docker"
) -> dict[str, Any]:
    if engine not in {"docker", "podman"}:
        raise ValidationError("qualification image build engine must be docker or podman")
    if shutil.which(engine) is None:
        raise ValidationError(f"OCI engine {engine!r} is unavailable")
    root = campaign_dir.resolve()
    manifest_path = root / "containers" / "manifest.json"
    if not manifest_path.is_file():
        prepare_qualification_containers(root, engine)
    manifest = _read_json_file(manifest_path)
    records = {row["project"]: row for row in manifest.get("projects", [])}
    if project not in records:
        raise ValidationError(f"no qualification container definition for project {project!r}")
    record = records[project]
    if not record.get("buildable"):
        raise ValidationError(f"qualification container is not admitted yet: {project}")
    _verify_host_bindings(record)
    required = _required_labels(record)
    try:
        existing = _inspect_image(engine, str(record["image"]))
        labels = existing.get("Config", {}).get("Labels", {}) or {}
        if all(labels.get(key) == value for key, value in required.items()):
            result = _build_result(
                record, existing, engine=engine, campaign_dir=campaign_dir,
                build_context="reused-existing-image", build_log=None,
            )
            _append_build(root, result)
            return result
    except ValidationError:
        pass

    build_log = root / "containers" / "build" / f"{project}.build.log"
    context = Path(tempfile.mkdtemp(prefix=f"clawgap-container-{project}-"))
    try:
        _stage_build_context(record, context)
        dockerfile = str(record["dockerfile_path"])
        arguments = [engine, "build", "-f", dockerfile]
        for key, value in required.items():
            arguments.extend(["--label", f"{key}={value}"])
        arguments.extend(["-t", str(record["image"]), "."])
        completed = subprocess.run(
            arguments, cwd=context, capture_output=True, text=True,
            timeout=1800, check=False,
        )
        atomic_write_text(build_log, completed.stdout + completed.stderr)
        if completed.returncode != 0:
            raise ValidationError(
                f"qualification container build failed: {completed.stderr[-1600:]}"
            )
        inspected = _inspect_image(engine, str(record["image"]))
        labels = inspected.get("Config", {}).get("Labels", {}) or {}
        drift = [key for key, value in required.items() if labels.get(key) != value]
        if drift:
            raise ValidationError(
                f"built container lacks qualification labels: {', '.join(drift)}"
            )
    finally:
        shutil.rmtree(context, ignore_errors=True)
    result = _build_result(
        record, inspected, engine=engine, campaign_dir=campaign_dir,
        build_context="ephemeral-tempdir", build_log=str(build_log.relative_to(root)),
    )
    _append_build(root, result)
    return result


def prebuild_qualification_containers(
    campaign_dir: Path,
    engine: str = "auto",
    *,
    project: str | None = None,
) -> dict[str, Any]:
    """Run the checked-in definitions as the mandatory pre-analysis build stage."""

    resolved = engine if engine in {"docker", "podman"} else _resolve_engine(engine)
    manifest = prepare_qualification_containers(campaign_dir, engine)
    requested = project
    if requested is None:
        candidates = [row for row in manifest["projects"] if row["buildable"]]
        if candidates and candidates[0]["project"] != "hermes-agent":
            raise ValidationError("Hermes Agent must remain first in pre-analysis build order")
    else:
        candidates = [row for row in manifest["projects"] if row["project"] == requested]
        if len(candidates) != 1:
            raise ValidationError(f"no qualification container definition for {requested!r}")
    builds = [build_qualification_image(campaign_dir, row["project"], resolved) for row in candidates]
    return {"manifest": manifest, "builds": builds}


def _resolve_engine(engine: str) -> str:
    if engine == "auto":
        if shutil.which("podman"):
            return "podman"
        if shutil.which("docker"):
            return "docker"
    raise ValidationError(f"no supported OCI engine is available for {engine!r}")
