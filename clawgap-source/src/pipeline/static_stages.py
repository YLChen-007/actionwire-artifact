"""Static gate, chain, and terminal sink-constraint stages."""

from __future__ import annotations

import ast
import csv
import hashlib
import json
import shlex
from pathlib import Path
from typing import Iterable

from src.gate_semantics.pipeline import run_pipeline as run_gate_pipeline
from src.gate_semantics.typescript_slicer import typescript_call_context
from src.projects import ProjectSpec

from .codeql import preflight_project, run_query


ELIGIBLE_VERDICTS = {"confirmed", "branch-confirmed"}
VERDICT_RANK = {"needs-review": 0, "branch-confirmed": 1, "confirmed": 2}


def _run_project_query(
    spec: ProjectSpec, query_name: str, output_csv: Path
) -> list[dict[str, str]]:
    return run_query(
        spec.codeql_database,
        query_name,
        output_csv,
        query_pack=spec.query_pack,
        expected_language=spec.codeql_language,
    )


def _write_csv(
    path: Path, rows: Iterable[dict[str, object]], fields: list[str]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _generation_command(spec: ProjectSpec, stage: str) -> str:
    return shlex.join(
        [
            "python",
            "-m",
            "src.pipeline",
            "--project",
            spec.project_id,
            "--source-root",
            str(spec.source_root),
            "--database",
            str(spec.codeql_database),
            "--output-root",
            str(spec.output_root),
            "--revision",
            spec.analysis_revision,
            stage,
        ]
    )


def infer_gates(spec: ProjectSpec) -> dict[str, object]:
    root = spec.output_root / "static" / "gates"
    preflight_project(spec, root / "project-model.csv")
    paths = {
        "dominance": root / "dominance.csv",
        "filter": root / "filter.csv",
        "transform": root / "transform.csv",
    }
    rows_by_mode = {
        "dominance": _run_project_query(spec, "get_gates.ql", paths["dominance"]),
        "filter": _run_project_query(spec, "fte_filter.ql", paths["filter"]),
        "transform": _run_project_query(spec, "fte_transform.ql", paths["transform"]),
    }
    normalized: list[dict[str, object]] = []
    union_fields: set[str] = {"detector"}
    for detector, rows in rows_by_mode.items():
        for row in rows:
            normalized.append({"detector": detector, **row})
            union_fields.update(row)
    ordered_fields = ["detector", *sorted(union_fields - {"detector"})]
    _write_csv(root / "gate-candidates.csv", normalized, ordered_fields)

    command = _generation_command(spec, "infer-gates")
    gate_manifest = run_gate_pipeline(
        source_root=spec.source_root,
        dominance_candidates=paths["dominance"],
        filter_candidates=paths["filter"],
        transform_candidates=paths["transform"],
        out_dir=spec.output_root / "gate-semantics",
        generation_command=command,
        build_slices_only=True,
        project_name=spec.project_id,
        project_revision=spec.analysis_revision,
        source_language=spec.source_language,
        independent_example_command=shlex.join(
            [
                "python",
                "-m",
                "src.pipeline",
                "--project",
                spec.project_id,
                "infer-gate-semantics",
                "--gate-number",
                "4",
            ]
        ),
    )
    manifest = {
        "schema_version": "clawgap-pipeline-gates/v2",
        "project": spec.project_id,
        "source_language": spec.source_language,
        "codeql_language": spec.codeql_language,
        "revision": spec.analysis_revision,
        "generation_command": command,
        "outputs": {key: str(value) for key, value in paths.items()},
        "candidate_catalog": str(root / "gate-candidates.csv"),
        "gate_index": str(spec.output_root / "gate-semantics" / "gate-index.csv"),
        "counts": {
            "dominance_rows": len(rows_by_mode["dominance"]),
            "filter_rows": len(rows_by_mode["filter"]),
            "transform_rows": len(rows_by_mode["transform"]),
            "all_candidate_rows": len(normalized),
            "eligible_catalog_gates": gate_manifest["counts"]["catalog_gates"],
            "slice_failures": gate_manifest["counts"]["slice_failures"],
        },
    }
    _write_json(root / "manifest.json", manifest)
    return manifest


def _digest_id(prefix: str, *parts: object, length: int = 16) -> str:
    raw = "|".join(str(part) for part in parts)
    return prefix + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:length]


def _canonical_chains(
    spec: ProjectSpec, raw_rows: list[dict[str, str]]
) -> list[dict[str, object]]:
    dedup: dict[str, dict[str, object]] = {}
    for row in raw_rows:
        sink_id = _digest_id(
            "S-",
            spec.project_id,
            spec.analysis_revision,
            row.get("sink_label"),
            row.get("sink_file"),
            row.get("sink_line"),
            row.get("sink_column"),
        )
        ordered_hops = tuple(
            hop.partition("@")[0]
            for hop in row.get("call_chain", "").partition("#")[2].split("->")
            if hop
        )
        chain_id = _digest_id(
            "C-",
            spec.project_id,
            spec.analysis_revision,
            row.get("tool_name"),
            row.get("handler_file"),
            row.get("handler_line"),
            row.get("source_parameter"),
            *ordered_hops,
            sink_id,
            length=12,
        )
        normalized = {
            "chain_id": chain_id,
            "sink_id": sink_id,
            **row,
        }
        previous = dedup.get(chain_id)
        if previous is not None:
            comparable_previous = {
                k: v for k, v in previous.items() if k != "sink_argument"
            }
            comparable_current = {
                k: v for k, v in normalized.items() if k != "sink_argument"
            }
            if comparable_previous != comparable_current:
                raise ValueError(f"stable chain ID collision for {chain_id}")
            facets = {
                value
                for raw in (
                    str(previous.get("sink_argument", "")),
                    str(normalized.get("sink_argument", "")),
                )
                for value in raw.split(";")
                if value
            }
            previous["sink_argument"] = ";".join(sorted(facets))
        else:
            dedup[chain_id] = normalized
    return [dedup[key] for key in sorted(dedup)]


def _call_context(
    source_root: Path,
    rel: str,
    line: int,
    *,
    source_language: str = "python",
    column: int = 0,
) -> tuple[str, tuple[str, ...]]:
    if source_language == "typescript":
        return typescript_call_context(source_root, rel, line, column)
    if source_language != "python":
        raise ValueError(f"unsupported call-context language: {source_language!r}")
    path = source_root / rel
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source.splitlines()[line - 1].strip(), ()

    candidates: list[tuple[ast.Call, tuple[str, ...]]] = []

    def visit(node: ast.AST, functions: tuple[str, ...]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions = (*functions, node.name)
        if isinstance(node, ast.Call) and int(getattr(node, "lineno", 0)) == line:
            candidates.append((node, functions))
        for child in ast.iter_child_nodes(node):
            visit(child, functions)

    visit(tree, ())
    if candidates:
        call, functions = candidates[0]
        segment = ast.get_source_segment(source, call)
        if segment:
            return " ".join(segment.split()), functions
    return source.splitlines()[line - 1].strip(), ()


def _call_shape(
    source_root: Path, rel: str, line: int, *, source_language: str = "python"
) -> str:
    return _call_context(source_root, rel, line, source_language=source_language)[0]


def _sink_card(
    label: str,
    call_shape: str,
    *,
    enclosing_functions: tuple[str, ...] = (),
) -> tuple[str, str, str]:
    # Capability cards follow the shared sink shape rather than adapter identity.
    if label == "page.goto" and (
        "gotoPageWithNavigationGuard" in enclosing_functions
        or "opts.page.goto(" in call_shape
    ):
        return (
            "lobsterai.browser-navigation.md",
            "playwright.Page.goto",
            "browser-navigation",
        )
    if label == "page.goto" and any(
        function in {"createPageViaPlaywright", "navigateViaPlaywright"}
        for function in enclosing_functions
    ):
        return "openclaw-cn.browser-navigation.md", label, "browser-navigation"
    if label in {"CDP.Target.createTarget", "fetch:/json/new"}:
        return "openclaw-cn.browser-navigation.md", label, "browser-navigation"
    if label in {"locator.click", "locator.dblclick"}:
        return "openclaw-cn.browser-interaction.md", label, "browser-interaction"
    if label in {"page.evaluate", "locator.evaluate"}:
        return "openclaw-cn.code-eval.md", label, "code-eval"
    if label in {
        "spawnImpl",
        "node-pty.spawn",
        "child_process.spawn:node-host",
        "child_process.spawn",
    }:
        api = {
            "spawnImpl": "node:child_process.spawn",
            "child_process.spawn": "node:child_process.spawn",
        }.get(label, label)
        return "node.child-process.md", api, "process-spawn"
    if label == "fs.writeFile:apply-patch":
        return "node.fs.write.md", "node:fs/promises.writeFile", "file-write"
    if label == "fetch:feishu-media":
        return "javascript.fetch.md", "fetch", "network-egress"
    if label == "getTransport.call:acp_prompt":
        return (
            "codeg.external-agent-execution.md",
            "CodeG.Transport.call:acp_prompt",
            "external-agent-execution",
        )
    if label == "spawn:external-agent-cli":
        return (
            "tinyclaw.external-agent-execution.md",
            "node:child_process.spawn:external-agent-cli",
            "external-agent-execution",
        )
    if label == "generateText.tools":
        return (
            "mercury.tool-capability-exposure.md",
            "ai.generateText.tools",
            "tool-capability-exposure",
        )
    if label == "askHandler":
        return (
            "mercury.command-approval.md",
            "PermissionManager.askHandler",
            "user-consent",
        )
    droidclaw_actions = {
        "executeTap": ("droidclaw.device-tap.md", "device-tap"),
        "findAndTap": ("droidclaw.device-tap.md", "device-tap"),
        "executeType": ("droidclaw.device-text-input.md", "device-text-input"),
        "executeSwipe": ("droidclaw.device-swipe.md", "device-swipe"),
        "executeScroll": ("droidclaw.device-swipe.md", "device-swipe"),
        "executeLaunch": ("droidclaw.app-launch.md", "app-launch"),
        "executeSwitchApp": ("droidclaw.app-launch.md", "app-launch"),
        "executePaste": ("droidclaw.clipboard-paste.md", "clipboard-paste"),
        "executeScreenshot": ("droidclaw.screen-capture.md", "screen-capture"),
        "executeLongPress": (
            "droidclaw.device-long-press.md",
            "device-long-press",
        ),
        "executeClipboardSet": (
            "droidclaw.clipboard-write.md",
            "clipboard-write",
        ),
        "copyVisibleText": ("droidclaw.clipboard-write.md", "clipboard-write"),
        "executeOpenUrl": (
            "droidclaw.browser-navigation.md",
            "browser-navigation",
        ),
        "executeKeyevent": ("droidclaw.device-keyevent.md", "device-keyevent"),
        "executeOpenSettings": (
            "droidclaw.settings-navigation.md",
            "settings-navigation",
        ),
        "executePullFile": ("droidclaw.device-file-pull.md", "device-file-pull"),
        "executePushFile": ("droidclaw.device-file-push.md", "device-file-push"),
        "executeShell": (
            "droidclaw.adb-shell-execution.md",
            "adb-shell-execution",
        ),
        "composeEmail": ("droidclaw.email-compose.md", "email-compose"),
    }
    if label in droidclaw_actions:
        card, capability_class = droidclaw_actions[label]
        return card, f"DroidClaw.{label}", capability_class
    nanoclaw_actions = {
        "create_agent": ("nanoclaw.agent-creation.md", "agent-creation"),
        "send_message": ("nanoclaw.message-delivery.md", "message-delivery"),
        "send_file": ("nanoclaw.file-delivery.md", "file-delivery"),
        "edit_message": ("nanoclaw.message-edit.md", "message-edit"),
        "add_reaction": ("nanoclaw.message-reaction.md", "message-reaction"),
        "ask_user_question": (
            "nanoclaw.interactive-question.md",
            "interactive-question",
        ),
        "send_card": ("nanoclaw.card-delivery.md", "card-delivery"),
        "schedule_task": ("nanoclaw.task-scheduling.md", "task-scheduling"),
        "list_tasks": ("nanoclaw.task-read.md", "task-read"),
        "cancel_task": ("nanoclaw.task-cancel.md", "task-cancel"),
        "pause_task": ("nanoclaw.task-pause.md", "task-pause"),
        "resume_task": ("nanoclaw.task-resume.md", "task-resume"),
        "update_task": ("nanoclaw.task-update.md", "task-update"),
        "install_packages": (
            "nanoclaw.package-installation.md",
            "package-installation",
        ),
        "add_mcp_server": (
            "nanoclaw.mcp-server-registration.md",
            "mcp-server-registration",
        ),
    }
    if label in nanoclaw_actions:
        card, capability_class = nanoclaw_actions[label]
        return card, f"NanoClaw.{label}", capability_class
    lettabot_actions = {
        "Bash": ("lettabot.command-execution.md", "command-execution"),
        "Read": ("lettabot.file-read.md", "file-read"),
        "Edit": ("lettabot.file-edit.md", "file-edit"),
        "Write": ("lettabot.file-write.md", "file-write"),
        "Glob": ("lettabot.file-enumeration.md", "file-enumeration"),
        "Grep": ("lettabot.content-search.md", "content-search"),
        "Task": ("lettabot.subagent-delegation.md", "subagent-delegation"),
    }
    if label in lettabot_actions:
        card, capability_class = lettabot_actions[label]
        return card, f"LettaCode.{label}", capability_class
    if label == "readFileSync:todo-store":
        return "node.fs.read.md", "node:fs.readFileSync", "file-read"
    if label == "writeFileSync:todo-store":
        return "node.fs.write.md", "node:fs.writeFileSync", "file-write"
    if label == "copyFileSync":
        return "node.fs.copy.md", "node:fs.copyFileSync", "file-copy"
    if label == "Statement.run:pending_approvals":
        return (
            "nanoclaw.approval-persistence.md",
            "better-sqlite3.Statement.run:pending_approvals",
            "approval-persistence",
        )
    if label == "Statement.run:container_configs":
        return (
            "nanoclaw.runtime-config-mutation.md",
            "better-sqlite3.Statement.run:container_configs.mcp_servers",
            "runtime-config-mutation",
        )
    if label == "adapter.deliver:approval-card":
        return (
            "nanoclaw.approval-presentation.md",
            "ChannelDeliveryAdapter.deliver:approval-card",
            "approval-presentation",
        )
    if label == "Attribute.extract":
        return "parallel.beta.extract.md", "parallel.beta.extract", "network-egress"
    if label == "Attribute.send_message_event":
        return (
            "matrix.send_message_event.md",
            "mautrix.Client.send_message_event",
            "delivery-render",
        )
    if label == "Attribute().chat_postMessage":
        return (
            "slack.chat_postMessage.md",
            "slack_sdk.WebClient.chat_postMessage",
            "delivery-render",
        )
    if label.endswith("get_contents"):
        return "exa.get_contents.md", "Exa.get_contents", "network-egress"
    if label == "scrape":
        return (
            "firecrawl.scrape.to-thread.md",
            "Firecrawl.scrape",
            "network-egress",
        )
    if label == "ws.send":
        return "websocket.send.cdp.md", "WebSocket.send", "code-eval"
    if label == "_run_browser_command":
        variants = {
            '"open"': ("_run_browser_command.open.md", "browser-nav"),
            '"eval"': ("_run_browser_command.eval.md", "code-eval"),
            '"snapshot"': (
                "_run_browser_command.snapshot.md",
                "browser-content-read",
            ),
        }
        matches = [value for marker, value in variants.items() if marker in call_shape]
        if len(matches) != 1:
            raise ValueError(
                "cannot resolve _run_browser_command capability variant: " + call_shape
            )
        card, capability_class = matches[0]
        return card, "_run_browser_command", capability_class
    if label == "camofox_navigate":
        return "camofox_navigate.md", "camofox_navigate", "browser-nav"
    if label == "file_ops.read_file":
        return "file_ops.read_file.md", "file_ops.read_file", "file-read"
    if label == "md.convert":
        return "markdown.md.convert.md", "markdown.Markdown.convert", "delivery-render"
    if label == "prompt_dangerous_approval":
        return (
            "prompt_dangerous_approval.md",
            "prompt_dangerous_approval",
            "user-consent",
        )
    if label == "self._api_post":
        return (
            "mattermost._api_post.posts.md",
            "Mattermost._api_post",
            "delivery-render",
        )
    if label == "session.post":
        return (
            "aiohttp.session.post.md",
            "aiohttp.ClientSession.post",
            "delivery-render",
        )
    if label == "session.put":
        return "aiohttp.session.put.md", "aiohttp.ClientSession.put", "delivery-render"
    if label == "subprocess.run":
        return "subprocess.run.md", "subprocess.run", "process-spawn"
    if label == "subprocess.Popen":
        return "subprocess.Popen.md", "subprocess.Popen", "process-spawn"
    if label == "asyncio.create_subprocess_exec":
        return (
            "asyncio.create_subprocess_exec.md",
            "asyncio.create_subprocess_exec",
            "process-spawn",
        )
    if label == "asyncio.create_subprocess_shell":
        return (
            "asyncio.create_subprocess_shell.md",
            "asyncio.create_subprocess_shell",
            "process-spawn",
        )
    if label.startswith("requests."):
        return "requests.get-post-request.md", label, "network-egress"
    if label in {"client.get", "info_sess.get", "session.get"}:
        return "http.session.request-get.md", label, "network-egress"
    if label == "client.post":
        return "httpx.AsyncClient.post.md", "httpx.AsyncClient.post", "network-egress"
    if label == "client.request":
        return (
            "httpx.AsyncClient.request.md",
            "httpx.AsyncClient.request",
            "network-egress",
        )
    if label.endswith(".goto"):
        return "playwright.page.goto.md", "playwright.page.goto", "browser-nav"
    if label.endswith(".read_text"):
        return "pathlib.Path.read_text.md", "pathlib.Path.read_text", "file-read"
    if label == "read_bytes" or label.endswith(".read_bytes"):
        return "pathlib.Path.read_bytes.md", "pathlib.Path.read_bytes", "file-read"
    if label.endswith(".open"):
        return "pathlib.Path.open.md", "pathlib.Path.open", "file-read"
    if label == "open":
        write_markers = ('"w"', "'w'", '"a"', "'a'", '"x"', "'x'")
        dynamic_write_mode = (
            "write_file" in enclosing_functions and "open(" in call_shape
        )
        if any(marker in call_shape for marker in write_markers) or dynamic_write_mode:
            return "builtins.open.write.md", "builtins.open", "file-write"
        return "builtins.open.read.md", "builtins.open", "file-read"
    if label in {
        "spawn",
        "spawnImpl",
        "spawnSync",
        "exec",
        "execSync",
        "execFile",
        "execFileSync",
        "fork",
    }:
        api_label = "spawn" if label == "spawnImpl" else label
        return (
            "node.child-process.md",
            f"node:child_process.{api_label}",
            "process-spawn",
        )
    if label in {"readFile", "readFileSync", "openSync"}:
        return "node.fs.read.md", f"node:fs.{label}", "file-read"
    if label in {
        "writeFile",
        "writeFileSync",
        "appendFile",
        "appendFileSync",
        "copyFile",
        "copyFileSync",
    }:
        return "node.fs.write.md", f"node:fs.{label}", "file-write"
    if label in {"rm", "rmSync", "unlink", "unlinkSync", "rmdir", "rmdirSync"}:
        return "node.fs.delete.md", f"node:fs.{label}", "file-delete"
    if label in {"fetch", "runWebFetch"}:
        return "javascript.fetch.md", label, "network-egress"
    if label == "Response.text":
        return (
            "javascript.response-text.md",
            "Response.text",
            "resource-consumption",
        )
    if label in {"browserOpenTab", "proxyRequest:/tabs/open"}:
        return "openclaw.browser-navigation.md", label, "browser-navigation"
    if label == "runMessageAction":
        return "openclaw.delivery.md", label, "delivery"
    if label == "Chrome MCP client.callTool":
        return "openclaw.chrome-mcp-rpc.md", label, "rpc-boundary"
    if label == "callGatewayTool:node.invoke":
        return "openclaw.node-invoke.md", label, "rpc-node-invoke"
    if label.startswith("callGatewayTool:"):
        return "openclaw.gateway-rpc.md", label, "rpc-boundary"
    if label in {"tool.execute", "base.execute"}:
        capability = (
            "file-read"
            if "createOpenClawReadTool" in enclosing_functions
            else "file-write"
        )
        return "openclaw.external-tool-boundary.md", label, capability
    raise ValueError(f"no sink capability-card mapping for {label!r}: {call_shape}")


def _sink_constraints(
    spec: ProjectSpec, chains: list[dict[str, object]]
) -> list[dict[str, object]]:
    cards_root = (
        Path(__file__).resolve().parents[1] / "sink_capacity" / "sink-capability-cards"
    )
    constraints: dict[str, dict[str, object]] = {}
    for chain in chains:
        sink_id = str(chain["sink_id"])
        if sink_id in constraints:
            previous = constraints[sink_id]
            identity = (
                str(chain["sink_label"]),
                str(chain["sink_file"]),
                int(str(chain["sink_line"])),
                int(str(chain.get("sink_column", "0") or 0)),
            )
            previous_identity = (
                str(previous["sink_label"]),
                str(previous["sink_file"]),
                int(previous["sink_line"]),
                int(previous["sink_column"]),
            )
            if identity != previous_identity:
                raise ValueError(
                    f"sink point {sink_id} has inconsistent constraint metadata"
                )
            controlled = {
                value
                for raw in (
                    str(previous["controlled_argument"]),
                    str(chain.get("sink_argument", "")),
                )
                for value in raw.split(";")
                if value
            }
            previous["controlled_argument"] = ";".join(sorted(controlled))
            continue
        rel = str(chain["sink_file"])
        line = int(str(chain["sink_line"]))
        shape, enclosing_functions = _call_context(
            spec.source_root,
            rel,
            line,
            source_language=spec.source_language,
            column=int(str(chain.get("sink_column", "0") or 0)),
        )
        card_name, api, capability_class = _sink_card(
            str(chain["sink_label"]),
            shape,
            enclosing_functions=enclosing_functions,
        )
        card = cards_root / card_name
        if not card.is_file():
            raise ValueError(f"sink capability card does not exist: {card}")
        constraints[sink_id] = {
            "constraint_id": "SC-" + sink_id[2:],
            "sink_id": sink_id,
            "sink_api": api,
            "sink_label": chain["sink_label"],
            "sink_file": rel,
            "sink_line": line,
            "sink_column": int(str(chain.get("sink_column", "0") or 0)),
            "controlled_argument": chain.get("sink_argument", ""),
            "capability_class": capability_class,
            "call_shape": shape,
            "capability_card": str(
                card.relative_to(Path(__file__).resolve().parents[2])
            ),
            "capability_card_sha256": hashlib.sha256(card.read_bytes()).hexdigest(),
        }
    return [constraints[key] for key in sorted(constraints)]


def _chain_parts(call_chain: str) -> tuple[list[str], list[str]]:
    _depth, _sep, body = call_chain.partition("#")
    functions: list[str] = []
    files: list[str] = []
    for hop in body.split("->")[:-1]:
        symbol, _at, file_name = hop.partition("@")
        functions.append(symbol.rsplit(".", 1)[-1])
        files.append(Path(file_name.split("$$", 1)[0]).name)
    return functions, files


def _codeql_display_matches(display: str, full: str) -> bool:
    """Match an abbreviated CodeQL ``toString()`` value to full AST text."""
    normalized_display = display.replace("\\n", "\n")
    if normalized_display == full:
        return True
    parts = normalized_display.split(" ... ")
    if len(parts) != 2:
        return False
    prefix, suffix = parts
    return full.startswith(prefix) and full.endswith(suffix)


def _catalog_match(
    candidate: dict[str, str], catalog: list[dict[str, str]], detector: str
) -> dict[str, str] | None:
    if detector == "dominance":
        name, file_value, line = (
            candidate.get("gate_fn"),
            candidate.get("gate_file"),
            candidate.get("gate_line"),
        )
    elif detector == "filter":
        name, file_value, line = (
            candidate.get("gate_fn"),
            candidate.get("gate_file"),
            candidate.get("gate_line"),
        )
    else:
        name = candidate.get("transform_fn")
        file_value = candidate.get("transform_call_file") or candidate.get(
            "transform_file"
        )
        line = candidate.get("transform_call_line") or candidate.get("transform_line")
    matches = [
        row
        for row in catalog
        if row.get("gate_name") == name
        and row.get("callsite_file") == file_value
        and int(row.get("callsite_line", "0") or 0) == int(line or 0)
    ]
    checked = candidate.get("checked_expr") or candidate.get("checked_var")
    if len(matches) > 1 and checked:
        checked_matches = [
            row
            for row in matches
            if _codeql_display_matches(checked, row.get("checked_expression", ""))
        ]
        if len(checked_matches) == 1:
            return checked_matches[0]
    return matches[0] if len(matches) == 1 else None


def _attach_chain_gates(
    chains: list[dict[str, object]],
    candidates: dict[str, list[dict[str, str]]],
    catalog: list[dict[str, str]],
) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for chain in chains:
        functions, ordered_hop_files = _chain_parts(str(chain["call_chain"]))
        hop_files = set(ordered_hop_files)
        matching: dict[str, dict[str, object]] = {}
        for detector, rows in candidates.items():
            for row in rows:
                if row.get("sink_file") != chain.get("sink_file") or int(
                    row.get("sink_line", "0") or 0
                ) != int(str(chain["sink_line"])):
                    continue
                call_file = (
                    row.get("gate_file")
                    if detector != "transform"
                    else row.get("transform_call_file") or row.get("transform_file")
                )
                catalog_row = _catalog_match(row, catalog, detector)
                owner = (
                    row.get("in_func")
                    or row.get("handler_func", "")
                    or (
                        catalog_row.get("enclosing_function", "") if catalog_row else ""
                    )
                )
                candidate_handler_file = row.get("handler_file", "")
                candidate_tool_name = row.get("tool_name", "")
                if candidate_handler_file and candidate_handler_file != chain.get(
                    "handler_file"
                ):
                    continue
                if candidate_tool_name and candidate_tool_name != chain.get(
                    "tool_name"
                ):
                    continue
                pre_handler = "[pre-handler]" in row.get("guard_kind", "")
                side_policy = (
                    bool(candidate_handler_file)
                    and bool(candidate_tool_name)
                    and (
                        row.get("guard_kind") == "decision-return-branch"
                        and call_file
                        in {
                            "src/infra/exec-approvals.ts",
                            "src/capabilities/permissions.ts",
                        }
                    )
                ) or (
                    chain.get("project_id") == "mercury-agent"
                    and detector == "transform"
                    and call_file == "src/capabilities/permissions.ts"
                ) or (
                    # OpenClaw-CN rows are emitted only by its revision-pinned
                    # exact handler/source/sink catalogue. Some selected-chain
                    # helpers sit behind HTTP callbacks or local helper calls
                    # that are intentionally summarized in the structural path;
                    # the handler/tool/sink identity remains explicit in QL.
                    chain.get("project_id") == "openclaw-cn"
                    and bool(candidate_handler_file)
                    and bool(candidate_tool_name)
                )
                if pre_handler:
                    if owner.rsplit(".", 1)[-1] != str(chain.get("handler_func", "")):
                        continue
                elif not side_policy:
                    if Path(call_file or "").name not in hop_files:
                        continue
                    if owner and owner.rsplit(".", 1)[-1] not in functions:
                        continue
                verdict = row.get("taint_verdict") or "confirmed"
                identity = (
                    catalog_row.get("gate_uid")
                    if catalog_row
                    else _digest_id(
                        "review-",
                        detector,
                        call_file,
                        row.get("gate_line") or row.get("transform_call_line"),
                        row.get("gate_fn") or row.get("transform_fn"),
                    )
                )
                attached = {
                    "chain_id": chain["chain_id"],
                    "call_chain": chain["call_chain"],
                    "sink_id": chain["sink_id"],
                    "detector": detector,
                    "gate_uid": catalog_row.get("gate_uid", "") if catalog_row else "",
                    "gate_id": catalog_row.get("gate_id", "") if catalog_row else "",
                    "gate_name": (
                        catalog_row.get("gate_name", "")
                        if catalog_row
                        else row.get("gate_fn") or row.get("transform_fn", "")
                    ),
                    "gate_file": call_file or "",
                    "gate_line": row.get("gate_line")
                    or row.get("transform_call_line")
                    or "0",
                    "enclosing_function": catalog_row.get("enclosing_function", owner)
                    if catalog_row
                    else owner,
                    "static_verdict": verdict,
                    "_chain_owner": (
                        row.get("handler_func", "")
                        if side_policy
                        else row.get("in_func", "")
                    ),
                    "_catalog_number": (
                        int(catalog_row.get("gate_number", "0") or 0)
                        if catalog_row
                        else 0
                    ),
                }
                previous = matching.get(str(identity))
                if previous is None or VERDICT_RANK.get(
                    str(attached["static_verdict"]), -1
                ) > VERDICT_RANK.get(str(previous["static_verdict"]), -1):
                    matching[str(identity)] = attached
        eligible = [
            row
            for row in matching.values()
            if row["static_verdict"] in ELIGIBLE_VERDICTS and row["gate_uid"]
        ]

        def order(row: dict[str, object]) -> tuple[int, int, int, str]:
            if chain.get("project_id") == "LobsterAI":
                policy_order = {
                    "defaultBrowserWebAccessConfig": 0,
                    "buildBrowserConfig": 1,
                    "MANAGED_BROWSER_POLICY_PROMPT": 2,
                    "assertBrowserNavigationAllowed": 3,
                    "isPrivateNetworkAllowedByPolicy": 4,
                }
                name = str(row.get("gate_name", ""))
                if name in policy_order:
                    return (
                        policy_order[name],
                        int(str(row["gate_line"])),
                        int(str(row["_catalog_number"])),
                        str(row["gate_uid"]),
                    )
            owners = [
                str(row.get("_chain_owner", "")),
                str(row["enclosing_function"]),
            ]
            position = next(
                (
                    index
                    for owner in owners
                    if owner
                    for index, name in enumerate(functions)
                    if name == owner.rsplit(".", 1)[-1]
                ),
                next(
                    (
                        index
                        for index, file_name in enumerate(ordered_hop_files)
                        if file_name == Path(str(row["gate_file"])).name
                    ),
                    10_000,
                ),
            )
            return (
                position,
                int(str(row["gate_line"])),
                int(str(row["_catalog_number"])),
                str(row["gate_uid"]),
            )

        ordered = sorted(eligible, key=order)
        if not ordered:
            output.append(
                {
                    "chain_id": chain["chain_id"],
                    "call_chain": chain["call_chain"],
                    "sink_id": chain["sink_id"],
                    "gate_seq": "",
                    "detector": "",
                    "gate_uid": "",
                    "gate_id": "",
                    "gate_name": "",
                    "gate_file": "",
                    "gate_line": "",
                    "enclosing_function": "",
                    "static_verdict": "",
                }
            )
        else:
            for seq, row in enumerate(ordered, 1):
                output.append({**row, "gate_seq": seq})
    return output


def infer_call_chains(spec: ProjectSpec) -> dict[str, object]:
    root = spec.output_root / "static" / "call-chains"
    preflight_project(spec, root / "project-model.csv")
    gate_index = spec.output_root / "gate-semantics" / "gate-index.csv"
    if not gate_index.is_file():
        raise FileNotFoundError("infer-gates must run before infer-call-chains")
    raw_path = root / "handler-sink-chains.raw.csv"
    raw = _run_project_query(spec, "get_handler_to_sink.ql", raw_path)
    chains = _canonical_chains(spec, raw)
    chain_fields = [
        "chain_id",
        "sink_id",
        "project_id",
        "tool_name",
        "handler_func",
        "handler_qualified_name",
        "handler_file",
        "handler_line",
        "source_parameter",
        "depth",
        "sink_label",
        "sink_file",
        "sink_line",
        "sink_column",
        "sink_argument",
        "call_chain",
    ]
    chain_path = root / "handler-sink-chains.csv"
    _write_csv(chain_path, chains, chain_fields)

    constraints = _sink_constraints(spec, chains)
    constraint_fields = (
        list(constraints[0])
        if constraints
        else [
            "constraint_id",
            "sink_id",
            "sink_api",
            "sink_label",
            "sink_file",
            "sink_line",
            "sink_column",
            "controlled_argument",
            "capability_class",
            "call_shape",
            "capability_card",
            "capability_card_sha256",
        ]
    )
    constraint_path = root / "sink-constraints.csv"
    _write_csv(constraint_path, constraints, constraint_fields)

    gate_root = spec.output_root / "static" / "gates"
    candidate_rows = {
        "dominance": _read_csv(gate_root / "dominance.csv"),
        "filter": _read_csv(gate_root / "filter.csv"),
        "transform": _read_csv(gate_root / "transform.csv"),
    }
    chain_gates = _attach_chain_gates(chains, candidate_rows, _read_csv(gate_index))
    chain_gate_fields = [
        "chain_id",
        "call_chain",
        "sink_id",
        "gate_seq",
        "detector",
        "gate_uid",
        "gate_id",
        "gate_name",
        "gate_file",
        "gate_line",
        "enclosing_function",
        "static_verdict",
    ]
    chain_gate_path = root / "chain-gates.csv"
    _write_csv(chain_gate_path, chain_gates, chain_gate_fields)

    command = _generation_command(spec, "infer-call-chains")
    index_lines = [
        "# Handler to Sink Call Chains",
        "",
        f"> Generation command: `{command}`",
        "",
        f"Chains: **{len(chains)}**. Sink constraints: **{len(constraints)}**.",
        "",
        "| Chain | Tool | Handler | Sink constraint | Eligible gates |",
        "|---|---|---|---|---:|",
    ]
    gate_counts: dict[str, int] = {}
    for row in chain_gates:
        if row.get("gate_uid"):
            key = str(row["chain_id"])
            gate_counts[key] = gate_counts.get(key, 0) + 1
    for chain in chains:
        index_lines.append(
            f"| `{chain['chain_id']}` | `{chain['tool_name']}` | "
            f"`{chain['handler_qualified_name']}` | `{chain['sink_id']}` "
            f"({chain['sink_label']}@{chain['sink_file']}:{chain['sink_line']}) | "
            f"{gate_counts.get(str(chain['chain_id']), 0)} |"
        )
    (root / "chain-index.md").write_text(
        "\n".join(index_lines) + "\n", encoding="utf-8"
    )
    manifest = {
        "schema_version": "clawgap-pipeline-call-chains/v2",
        "project": spec.project_id,
        "source_language": spec.source_language,
        "codeql_language": spec.codeql_language,
        "revision": spec.analysis_revision,
        "generation_command": command,
        "outputs": {
            "handler_sink_chains": str(chain_path),
            "chain_gates": str(chain_gate_path),
            "sink_constraints": str(constraint_path),
            "index": str(root / "chain-index.md"),
        },
        "counts": {
            "chains": len(chains),
            "sink_constraints": len(constraints),
            "eligible_chain_gate_rows": sum(
                bool(row.get("gate_uid")) for row in chain_gates
            ),
            "zero_gate_chains": sum(
                gate_counts.get(str(row["chain_id"]), 0) == 0 for row in chains
            ),
        },
    }
    _write_json(root / "manifest.json", manifest)
    return manifest
