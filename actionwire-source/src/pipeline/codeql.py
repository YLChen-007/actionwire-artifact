"""CodeQL execution helpers used by the project-neutral pipeline."""

from __future__ import annotations

import csv
import json
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path

from src.projects import ProjectSpec


REPO_ROOT = Path(__file__).resolve().parents[2]
CODEQL = REPO_ROOT / "bin" / "codeql"
QL_PACK = REPO_ROOT / "src" / "ql"


class CodeQLPipelineError(RuntimeError):
    pass


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        detail = (completed.stderr or completed.stdout)[-4000:]
        raise CodeQLPipelineError(
            f"CodeQL command failed ({completed.returncode}): {' '.join(command)}\n{detail}"
        )
    return completed


@lru_cache(maxsize=None)
def database_languages(database: Path) -> tuple[str, ...]:
    """Return extractor languages recorded by a finalized CodeQL database."""

    if not database.is_dir():
        raise CodeQLPipelineError(f"CodeQL database does not exist: {database}")
    resolved = _run(
        [str(CODEQL), "resolve", "database", "--format=json", str(database)]
    )
    try:
        payload = json.loads(resolved.stdout)
    except json.JSONDecodeError as exc:
        raise CodeQLPipelineError(
            f"CodeQL returned invalid database metadata for {database}: {exc}"
        ) from exc
    languages = payload.get("languages", [])
    if not isinstance(languages, list) or not all(
        isinstance(language, str) for language in languages
    ):
        raise CodeQLPipelineError(
            f"CodeQL database metadata has no valid languages list: {database}"
        )
    return tuple(sorted(languages))


def run_query(
    database: Path,
    query_name: str,
    output_csv: Path,
    *,
    query_pack: Path = QL_PACK,
    expected_language: str | None = None,
) -> list[dict[str, str]]:
    if not database.is_dir():
        raise CodeQLPipelineError(f"CodeQL database does not exist: {database}")
    if expected_language is not None:
        languages = database_languages(database.resolve())
        if languages != (expected_language,):
            rendered = ", ".join(languages) or "none"
            raise CodeQLPipelineError(
                "CodeQL database language mismatch: "
                f"expected {expected_language!r}, found {rendered!r} in {database}"
            )
    query = query_pack / query_name
    if not query.is_file():
        raise CodeQLPipelineError(f"CodeQL query does not exist: {query}")
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="clawgap-codeql-") as temp:
        bqrs = Path(temp) / "result.bqrs"
        _run(
            [
                str(CODEQL),
                "query",
                "run",
                f"--database={database}",
                f"--additional-packs={query_pack}",
                "-o",
                str(bqrs),
                str(query),
            ]
        )
        decoded = _run([str(CODEQL), "bqrs", "decode", "--format=csv", str(bqrs)])
    output_csv.write_text(decoded.stdout, encoding="utf-8")
    with output_csv.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def preflight_project(spec: ProjectSpec, output_csv: Path) -> dict[str, str]:
    rows = run_query(
        spec.codeql_database,
        "get_project_model.ql",
        output_csv,
        query_pack=spec.query_pack,
        expected_language=spec.codeql_language,
    )
    if len(rows) != 1:
        found = ", ".join(row.get("project_id", "?") for row in rows) or "none"
        raise CodeQLPipelineError(
            f"expected exactly one CodeQL project adapter, found {len(rows)}: {found}"
        )
    row = rows[0]
    if row.get("project_id") != spec.project_id:
        raise CodeQLPipelineError(
            f"CodeQL database selects {row.get('project_id')!r}, not {spec.project_id!r}"
        )
    if row.get("adapter_name") != spec.codeql_adapter:
        raise CodeQLPipelineError(
            f"CodeQL adapter mismatch: {row.get('adapter_name')!r} != {spec.codeql_adapter!r}"
        )
    return row
