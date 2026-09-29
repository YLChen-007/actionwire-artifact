"""Single source of truth for benchmark project paths and analysis identity."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class LLMConfig:
    """Non-secret LLM transport defaults for one project."""

    transport: str = "openai-compatible"
    base_url: str = "https://api.deepseek.com/v1"
    model: str = "deepseek-v4-flash"
    api_key_env: str = "DEEPSEEK_API_KEY"


@dataclass(frozen=True)
class ProjectSpec:
    """All project-dependent inputs required by the five-stage pipeline."""

    project_id: str
    source_root: Path
    analysis_revision: str
    codeql_database: Path
    design_root: Path
    output_root: Path
    ground_truth_root: Path
    codeql_adapter: str
    source_language: str
    codeql_language: str
    query_pack: Path
    extraction_exclusions: tuple[str, ...] = ()
    extraction_inclusions: tuple[str, ...] = ()
    semantic_profiles: tuple[str, ...] = ()
    llm: LLMConfig = LLMConfig()

    def resolved(self) -> "ProjectSpec":
        def absolute(path: Path) -> Path:
            return path if path.is_absolute() else REPO_ROOT / path

        return replace(
            self,
            source_root=absolute(self.source_root).resolve(),
            codeql_database=absolute(self.codeql_database).resolve(),
            design_root=absolute(self.design_root).resolve(),
            output_root=absolute(self.output_root).resolve(),
            ground_truth_root=absolute(self.ground_truth_root).resolve(),
            query_pack=absolute(self.query_pack).resolve(),
        )

    def with_overrides(
        self,
        *,
        source_root: Path | None = None,
        codeql_database: Path | None = None,
        design_root: Path | None = None,
        output_root: Path | None = None,
        ground_truth_root: Path | None = None,
        analysis_revision: str | None = None,
    ) -> "ProjectSpec":
        return replace(
            self,
            source_root=source_root or self.source_root,
            codeql_database=codeql_database or self.codeql_database,
            design_root=design_root or self.design_root,
            output_root=output_root or self.output_root,
            ground_truth_root=ground_truth_root or self.ground_truth_root,
            analysis_revision=analysis_revision or self.analysis_revision,
        ).resolved()


_PROJECTS = {
    "AstrBot": ProjectSpec(
        project_id="AstrBot",
        source_root=Path("benchmark/python/AstrBot"),
        analysis_revision="0e973bd4d483d18e1672c4dfa2eb7aae31bc1f83",
        codeql_database=Path("codeql-db/AstrBot-db"),
        design_root=Path("design/AstrBot"),
        output_root=Path("output/AstrBot"),
        ground_truth_root=Path("design/AstrBot/groundtruth"),
        codeql_adapter="astrbot",
        source_language="python",
        codeql_language="python",
        query_pack=Path("src/ql"),
        extraction_exclusions=(
            ".venv",
            "node_modules",
            "site-packages",
            "__pycache__",
            "pysa-runs_AstrBot",
        ),
    ),
    "hermes-agent": ProjectSpec(
        project_id="hermes-agent",
        source_root=Path("benchmark/python/hermes-agent"),
        # Keep the revision embedded in the current gate repository so migration
        # does not churn GateSemanticIR identities.
        analysis_revision="04439ac77f08915b4886bc3c79165a9538af6219",
        codeql_database=Path("codeql-db/hermes-agent-db"),
        design_root=Path("design/hermes-agent"),
        output_root=Path("output/hermes"),
        ground_truth_root=Path("design/hermes-agent/groudtruth/new-vuls"),
        codeql_adapter="hermes",
        source_language="python",
        codeql_language="python",
        query_pack=Path("src/ql"),
        extraction_exclusions=(".venv", "node_modules", "site-packages"),
        semantic_profiles=("hermes-compound-v1", "hermes-behavior-v1"),
    ),
    "chatgpt-on-wechat": ProjectSpec(
        project_id="chatgpt-on-wechat",
        source_root=Path("benchmark/python/chatgpt-on-wechat"),
        analysis_revision="55aaf60a57ea6e9f4b8a54797572d98f65e88d2f",
        codeql_database=Path("codeql-db/chatgpt-on-wechat-db"),
        design_root=Path("design/chatgpt-on-wechat"),
        output_root=Path("output/chatgpt-on-wechat"),
        ground_truth_root=Path("design/chatgpt-on-wechat/groundtruth"),
        codeql_adapter="cowagent",
        source_language="python",
        codeql_language="python",
        query_pack=Path("src/ql"),
        extraction_exclusions=(
            ".agentfuzz-main-venv",
            ".venv",
            "node_modules",
            "site-packages",
            "__pycache__",
        ),
    ),
    "QwenPaw": ProjectSpec(
        project_id="QwenPaw",
        source_root=Path("benchmark/python/QwenPaw"),
        analysis_revision="6d1e936f1ba08ad2e0398367f8c27529e9d1d5df",
        codeql_database=Path("codeql-db/QwenPaw-db"),
        design_root=Path("design/QwenPaw"),
        output_root=Path("output/QwenPaw"),
        ground_truth_root=Path("design/QwenPaw/groundtruth"),
        codeql_adapter="qwenpaw",
        source_language="python",
        codeql_language="python",
        query_pack=Path("src/ql"),
        extraction_exclusions=(
            ".venv",
            "node_modules",
            "site-packages",
            "__pycache__",
        ),
    ),
    "nanobot": ProjectSpec(
        project_id="nanobot",
        source_root=Path("benchmark/python/nanobot"),
        analysis_revision="337c4600f3d78797bb4ed845b5a02118c7ac2d00",
        codeql_database=Path("codeql-db/nanobot-db"),
        design_root=Path("design/nanobot"),
        output_root=Path("output/nanobot"),
        ground_truth_root=Path("design/nanobot/groundtruth"),
        codeql_adapter="nanobot",
        source_language="python",
        codeql_language="python",
        query_pack=Path("src/ql"),
        extraction_exclusions=(
            ".venv",
            "node_modules",
            "site-packages",
            "__pycache__",
        ),
    ),
    "poco-agent": ProjectSpec(
        project_id="poco-agent",
        source_root=Path("benchmark/python/poco-agent"),
        analysis_revision="7a61cb9f0e871f75f5623448f849f1e3d1958e35",
        codeql_database=Path("codeql-db/poco-agent-db"),
        design_root=Path("design/poco-agent"),
        output_root=Path("output/poco-agent"),
        ground_truth_root=Path("design/poco-agent/groundtruth"),
        codeql_adapter="poco-agent",
        source_language="python",
        codeql_language="python",
        query_pack=Path("src/ql"),
        extraction_exclusions=(
            ".venv",
            "node_modules",
            "site-packages",
            "__pycache__",
        ),
    ),
    "openclaw": ProjectSpec(
        project_id="openclaw",
        source_root=Path("benchmark/typescript/openclaw"),
        analysis_revision="d842b28a1517f95aae2a5bcd97f2f726e42b93d8",
        codeql_database=Path("codeql-db/openclaw-db"),
        design_root=Path("design/openclaw"),
        output_root=Path("output/openclaw"),
        ground_truth_root=Path("design/openclaw/groundtruth"),
        codeql_adapter="openclaw-ts",
        source_language="typescript",
        codeql_language="javascript",
        query_pack=Path("src/ql-js"),
        extraction_exclusions=(
            "node_modules",
            "extensions",
            "apps",
            "dist",
            ".git",
            ".test.ts",
            ".spec.ts",
        ),
    ),
    "openclaw-cn": ProjectSpec(
        project_id="openclaw-cn",
        source_root=Path("benchmark/typescript/openclaw-cn"),
        analysis_revision="558f272e6c90e7e0c37644e505e161b91ef738f0",
        codeql_database=Path("codeql-db/openclaw-cn-db"),
        design_root=Path("design/openclaw-cn"),
        output_root=Path("output/openclaw-cn"),
        ground_truth_root=Path("design/openclaw-cn/groundtruth"),
        codeql_adapter="openclaw-cn-ts",
        source_language="typescript",
        codeql_language="javascript",
        query_pack=Path("src/ql-js"),
        extraction_exclusions=(
            "node_modules",
            "extensions",
            "apps",
            "vendor",
            "dist",
            "scripts",
            ".git",
            ".test.ts",
            ".spec.ts",
        ),
        extraction_inclusions=(
            "extensions/feishu/src/outbound.ts",
            "extensions/feishu/src/media.ts",
        ),
    ),
    "nanoclaw": ProjectSpec(
        project_id="nanoclaw",
        source_root=Path("benchmark/typescript/nanoclaw"),
        analysis_revision="36cbf17e107fd0f8daea4ceb2ac523d9f0d88915",
        codeql_database=Path("codeql-db/nanoclaw-db"),
        design_root=Path("design/nanoclaw"),
        output_root=Path("output/nanoclaw"),
        ground_truth_root=Path("design/nanoclaw/groundtruth"),
        codeql_adapter="nanoclaw-ts",
        source_language="typescript",
        codeql_language="javascript",
        query_pack=Path("src/ql-js"),
        extraction_exclusions=(
            "node_modules",
            "setup",
            "scripts",
            ".claude",
            "dist",
            ".git",
            ".test.ts",
            ".spec.ts",
        ),
    ),
    "mercury-agent": ProjectSpec(
        project_id="mercury-agent",
        source_root=Path("benchmark/typescript/mercury-agent"),
        analysis_revision="587fad1bf9449598d1b27833f8c7db55d164741a",
        codeql_database=Path("codeql-db/mercury-agent-db"),
        design_root=Path("design/mercury-agent"),
        output_root=Path("output/mercury-agent"),
        ground_truth_root=Path("design/mercury-agent/groundtruth"),
        codeql_adapter="mercury-agent-ts",
        source_language="typescript",
        codeql_language="javascript",
        query_pack=Path("src/ql-js"),
        extraction_exclusions=(
            "node_modules",
            "ui",
            "website",
            "docs",
            "scripts",
            "dist",
            ".git",
            ".test.ts",
            ".spec.ts",
        ),
    ),
    "droidclaw": ProjectSpec(
        project_id="droidclaw",
        source_root=Path("benchmark/typescript/droidclaw"),
        analysis_revision="c7c991933e4a0c03cec6044aa7fb9067d391f4d4",
        codeql_database=Path("codeql-db/droidclaw-db"),
        design_root=Path("design/droidclaw"),
        output_root=Path("output/droidclaw"),
        ground_truth_root=Path("design/droidclaw/groundtruth"),
        codeql_adapter="droidclaw-ts",
        source_language="typescript",
        codeql_language="javascript",
        query_pack=Path("src/ql-js"),
        extraction_exclusions=(
            "node_modules",
            "android",
            "server",
            "web",
            "site",
            "examples",
            "scripts",
            "dist",
            ".git",
            ".test.ts",
            ".spec.ts",
        ),
    ),
    "lettabot": ProjectSpec(
        project_id="lettabot",
        source_root=Path("benchmark/typescript/lettabot"),
        analysis_revision="99c3b5dd73550fe0a4eac2ee31b1c3229ca9e550",
        codeql_database=Path("codeql-db/lettabot-db"),
        design_root=Path("design/lettabot"),
        output_root=Path("output/lettabot"),
        ground_truth_root=Path("design/lettabot/groundtruth"),
        codeql_adapter="lettabot-ts",
        source_language="typescript",
        codeql_language="javascript",
        query_pack=Path("src/ql-js"),
        extraction_exclusions=(
            "node_modules",
            ".skills",
            "skills",
            "scripts",
            "e2e",
            "docs",
            "src/test",
            "src/setup",
            "dist",
            ".git",
            ".test.ts",
            ".spec.ts",
        ),
    ),
}


def list_projects() -> tuple[str, ...]:
    return tuple(sorted(_PROJECTS))


def get_project(project_id: str) -> ProjectSpec:
    try:
        return _PROJECTS[project_id].resolved()
    except KeyError as exc:
        available = ", ".join(list_projects())
        raise KeyError(f"unknown project {project_id!r}; available: {available}") from exc
