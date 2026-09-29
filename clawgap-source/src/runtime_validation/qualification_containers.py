"""Reusable, immutable OCI baseline lifecycle for adapter qualification."""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from typing import Any, Mapping

from .contracts import ValidationError, redact_text


CREDENTIAL_MARKERS = ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "CREDENTIAL")


@dataclass(frozen=True)
class ContainerBinding:
    image: str
    image_id: str
    source_digest: str
    dependency_digest: str
    revision: str
    python: str
    source_root: str
    project_binding: Mapping[str, Any]


class OciContainer:
    """One reusable project-adapter baseline with disposable per-pair state."""

    def __init__(
        self,
        engine: str,
        case: Mapping[str, Any],
        image_binding: Mapping[str, Any],
    ) -> None:
        self.engine = engine
        self.case = case
        self.image_binding = image_binding
        self.name = "clawgap-qualification-" + uuid.uuid4().hex[:16]
        self.container_id: str | None = None
        self.started_image_id: str | None = None
        self.canary = "clawgap-" + uuid.uuid4().hex

    @property
    def image(self) -> str:
        return str(self.image_binding["image"])

    def _run(
        self,
        arguments: list[str],
        *,
        timeout: int = 60,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.engine, *arguments],
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    @staticmethod
    def _credential_environment(environment: list[Any]) -> list[str]:
        rows: list[str] = []
        for item in environment:
            if not isinstance(item, str) or "=" not in item:
                continue
            key, _value = item.split("=", 1)
            if any(marker in key.upper() for marker in CREDENTIAL_MARKERS) and not key.startswith("CLAWGAP_"):
                rows.append(key)
        return sorted(rows)

    def preflight(self) -> tuple[bool, str, ContainerBinding | None]:
        if shutil.which(self.engine) is None:
            return False, f"OCI engine {self.engine!r} is unavailable", None
        probe = self._run(["image", "inspect", self.image, "--format", "{{json .}}"])
        if probe.returncode != 0:
            return False, f"revision-bound OCI image is unavailable: {self.image}", None
        try:
            image = json.loads(probe.stdout)
            config = image["Config"]
            labels = config.get("Labels", {}) or {}
            image_id = str(image["Id"])
            environment = config.get("Env", []) or []
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            return False, f"OCI image inspection failed: {type(exc).__name__}: {exc}", None
        required = {
            "org.clawgap.qualification.bridge": "v1",
            "org.clawgap.revision": self.image_binding["revision"],
            "org.clawgap.source-digest": self.image_binding["source_digest"],
            "org.clawgap.dependency-digest": self.image_binding["dependency_digest"],
            "org.clawgap.bridge-digest": self.image_binding["bridge_digest"],
            "org.clawgap.definition-digest": self.image_binding["definition_digest"],
            "org.clawgap.bridge-dependencies": "jsonschema==4.25.1",
        }
        drift = [key for key, expected in required.items() if labels.get(key) != expected]
        if drift:
            return False, f"OCI image lacks required qualification bindings: {', '.join(drift)}", None
        if str(config.get("User", "")) != "65532:65532":
            return False, "OCI image does not force the non-root qualification user", None
        credentials = self._credential_environment(environment)
        if credentials:
            return False, f"OCI image inherits credential variables: {', '.join(credentials)}", None
        python = str(labels.get("org.clawgap.qualification.python", "python3"))
        return True, "revision-bound OCI qualification bridge is available", ContainerBinding(
            self.image,
            image_id,
            str(self.image_binding["source_digest"]),
            str(self.image_binding["dependency_digest"]),
            str(self.image_binding["revision"]),
            python,
            str(self.image_binding["source_root"]),
            self.image_binding,
        )

    def start(self, binding: ContainerBinding) -> Mapping[str, Any]:
        result = self._run(
            [
                "run",
                "-d",
                "--name",
                self.name,
                "--read-only",
                "--network",
                "none",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "256",
                "--user",
                "65532:65532",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=256m,uid=65532,gid=65532",
                "--tmpfs",
                "/run:rw,noexec,nosuid,size=32m,uid=65532,gid=65532",
                "--label",
                "org.clawgap.runtime=adapter-qualification-v1",
                binding.image,
                "sh",
                "-c",
                "exec sleep infinity",
            ],
            timeout=120,
        )
        if result.returncode != 0:
            raise ValidationError(f"OCI baseline start failed: {redact_text(result.stderr[-1200:])}")
        self.container_id = result.stdout.strip()
        self.started_image_id = binding.image_id
        write_canary = self._run(
            [
                "exec",
                self.name,
                "sh",
                "-c",
                f"printf '%s' '{self.canary}' > /run/clawgap-baseline-canary",
            ],
            timeout=30,
        )
        if write_canary.returncode != 0:
            self.stop()
            raise ValidationError("OCI baseline canary initialization failed")
        health = self._run(["exec", self.name, "python3", "-c", "import pathlib; assert pathlib.Path('/run/clawgap-baseline-canary').is_file()"])
        if health.returncode != 0:
            self.stop()
            raise ValidationError("OCI baseline healthcheck failed")
        return {
            "engine": self.engine,
            "image": binding.image,
            "image_id": binding.image_id,
            "container_id": self.container_id,
            "source_root": binding.source_root,
            "network": "none",
            "root_filesystem": "read-only",
            "host_mounts": False,
            "credentials_inherited": False,
            "baseline": "healthy",
        }

    def _probe(self, pair_id: str) -> dict[str, Any]:
        request = {
            "schema_version": "clawgap-qualification-container-probe/v1",
            "source_root": self.image_binding["source_root"],
            "bindings": {
                "source_binding": self.image_binding["source_binding"],
                "dependency_binding": self.image_binding["dependency_binding"],
            },
            "canary": self.canary,
            "pair_id": pair_id,
        }
        result = self._run(
            [
                "exec",
                "-i",
                self.name,
                "python3",
                "-m",
                "src.runtime_validation.qualification_container_probe",
            ],
            input_text=json.dumps(request, sort_keys=True),
            timeout=60,
        )
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ValidationError(
                f"OCI reset probe returned invalid JSON: {exc}; stderr={redact_text(result.stderr[-500:])}"
            ) from exc
        if result.returncode != 0 or value.get("status") != "passed":
            raise ValidationError(f"OCI reset failed: {json.dumps(value, sort_keys=True)[:1600]}")
        if not isinstance(value, dict):
            raise ValidationError("OCI reset probe result must be an object")
        return value

    def reset(self, pair_id: str) -> Mapping[str, Any]:
        if self.container_id is None:
            raise ValidationError("OCI baseline was not started")
        probe = self._probe(pair_id)
        inspect = self._run(["image", "inspect", self.image, "--format", "{{.Id}}"])
        if inspect.returncode != 0 or inspect.stdout.strip() != self.started_image_id:
            raise ValidationError("OCI image identity changed during qualification")
        health = self._run(
            ["exec", self.name, "python3", "-c", "import pathlib; assert pathlib.Path('/run/clawgap-baseline-canary').is_file()"]
        )
        if health.returncode != 0:
            raise ValidationError("OCI baseline healthcheck failed after reset")
        return {
            "reset": "passed",
            "pair_state_removed": True,
            "target_children": "none",
            "host_effect_canary": "unchanged",
            "source_hashes": "unchanged",
            "image_id": "unchanged",
            "probe": probe,
        }

    def stop(self) -> None:
        if self.container_id is None:
            return
        self._run(["rm", "-f", self.name], timeout=120)
        self.container_id = None
