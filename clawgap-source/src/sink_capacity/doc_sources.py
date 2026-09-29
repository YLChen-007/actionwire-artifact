"""
Acquire the ground-truth material for a sink API's capability card.

Answers the open question "how to get sink API docs" with a layered, mostly
offline, reproducible strategy:

  1. Installed-package introspection (primary, version-correct): import the actual
     API object from the environment and read its signature + docstring via
     `inspect`. Works for stdlib and any installed third-party package — no network,
     reproducible, matches the exact pinned version.
  2. Curated doc-URL registry (provenance only, not fetched live): the canonical
     doc/spec URL for each API, cited in the card's `provenance`.
  3. Project source (for project-internal wrapper APIs with no library doc): grep
     the target source tree for the wrapper's `def` and return its body.

Security knowledge (GTFOBins / OWASP SSRF / CWE) is supplied to the LLM as static
hints in prompts.py; the LLM's parametric knowledge fills the narrative, grounded
against (1)-(3).
"""
from __future__ import annotations

import importlib
import inspect
import json as _json
import re
import re as _re
import urllib.request as _urlreq
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional


# Canonical doc/spec URL per import_path (provenance; NOT fetched at runtime).
DOC_URLS: dict[str, str] = {
    "subprocess.Popen": "https://docs.python.org/3/library/subprocess.html#subprocess.Popen",
    "subprocess.run": "https://docs.python.org/3/library/subprocess.html#subprocess.run",
    "os.system": "https://docs.python.org/3/library/os.html#os.system",
    "asyncio.create_subprocess_exec": "https://docs.python.org/3/library/asyncio-subprocess.html#asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell": "https://docs.python.org/3/library/asyncio-subprocess.html#asyncio.create_subprocess_shell",
    "builtins.eval": "https://docs.python.org/3/library/functions.html#eval",
    "builtins.exec": "https://docs.python.org/3/library/functions.html#exec",
    "builtins.open": "https://docs.python.org/3/library/functions.html#open",
    "pathlib.Path.read_text": "https://docs.python.org/3/library/pathlib.html#pathlib.Path.read_text",
    "pathlib.Path.read_bytes": "https://docs.python.org/3/library/pathlib.html#pathlib.Path.read_bytes",
    "pathlib.Path.open": "https://docs.python.org/3/library/pathlib.html#pathlib.Path.open",
    "httpx.AsyncClient.get": "https://www.python-httpx.org/api/#asyncclient",
    "httpx.Client.request": "https://www.python-httpx.org/api/#client",
    "requests.get": "https://requests.readthedocs.io/en/latest/api/#requests.get",
    "markdown.Markdown.convert": "https://python-markdown.github.io/reference/#convert",
}

# Extra static security-knowledge references per capability_class (for provenance).
SECURITY_REFS: dict[str, list[str]] = {
    "process-spawn": ["GTFOBins (find/xargs/awk/tar/git exec)", "CWE-78 OS Command Injection"],
    "file-read": ["POSIX open(2) symlink resolution", "CWE-22 Path Traversal"],
    "file-write": ["CWE-22 Path Traversal", "POSIX open(2) O_CREAT/O_TRUNC"],
    "network-egress": ["OWASP SSRF cheat sheet (internal/metadata/DNS-rebinding/redirect)", "CWE-918 SSRF"],
    "browser-nav": ["OWASP SSRF cheat sheet", "URL scheme abuse (file:// data: about:)"],
    "code-eval": ["CWE-95 Eval Injection", "CDP Runtime.evaluate spec"],
    "sql-exec": ["CWE-89 SQL Injection"],
    "template-injection": ["CWE-1336 Server-Side Template Injection"],
    "delivery-render": ["CWE-79 XSS / output rendering; platform mention semantics"],
}


def _resolve(dotted: str):
    """Import the object named by a dotted path (longest importable module prefix + attrs)."""
    parts = dotted.split(".")
    obj = None
    for i in range(len(parts), 0, -1):
        try:
            obj = importlib.import_module(".".join(parts[:i]))
            rest = parts[i:]
            break
        except Exception:
            continue
    else:
        # builtins fallback
        import builtins
        obj = builtins
        rest = parts[1:] if parts[0] == "builtins" else parts
    for p in rest:
        obj = getattr(obj, p)
    return obj


def introspect(import_path: Optional[str]) -> Optional[dict]:
    """Return {'signature','doc','version','resolved'} for an API, or None."""
    if not import_path:
        return None
    try:
        obj = _resolve(import_path)
    except Exception as e:  # pragma: no cover
        return {"error": f"resolve failed: {e}", "import_path": import_path}
    sig = ""
    try:
        sig = f"{import_path.split('.')[-1]}{inspect.signature(obj)}"  # type: ignore[arg-type]
    except (ValueError, TypeError):
        sig = ""  # many C builtins have no introspectable signature
    doc = inspect.getdoc(obj) or ""
    if len(doc) > 4000:
        doc = doc[:4000] + "\n... [doc truncated]"
    version = ""
    try:
        top = importlib.import_module(import_path.split(".")[0])
        version = getattr(top, "__version__", "") or ""
    except Exception:
        pass
    return {"import_path": import_path, "signature": sig, "doc": doc, "version": version}


def project_source(method_hint: str, source_roots: list[str], max_lines: int = 60) -> Optional[dict]:
    """Best-effort: grep source roots for `def <method_hint>(` and return the body span."""
    if not method_hint:
        return None
    pat = re.compile(rf"^(\s*)(?:async\s+)?def\s+{re.escape(method_hint)}\s*\(")
    for root in source_roots:
        rp = Path(root)
        if not rp.exists():
            continue
        for py in rp.rglob("*.py"):
            if any(s in str(py) for s in ("/.venv/", "/site-packages/", "/tests/", "/test_")):
                continue
            try:
                lines = py.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                continue
            for idx, line in enumerate(lines):
                if pat.match(line):
                    body = "\n".join(lines[idx: idx + max_lines])
                    return {
                        "file": str(py),
                        "line": idx + 1,
                        "body": body,
                    }
    return None


# --------------------------------------------------------------------------- #
# Local doc snapshot cache: crawl official docs once, reuse from disk.
# --------------------------------------------------------------------------- #
DEFAULT_DOCS_CACHE = "src/sink_capacity/api-docs-snapshots"


class _TextExtractor(HTMLParser):
    _SKIP = {"script", "style", "noscript", "head", "nav", "footer"}
    _BREAK = {"p", "div", "section", "dl", "dt", "dd", "li", "h1", "h2",
              "h3", "h4", "br", "tr", "pre"}

    def __init__(self):
        super().__init__()
        self.parts: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):  # noqa: ARG002 (HTMLParser signature)
        if tag in self._SKIP:
            self.skip += 1
        elif tag in self._BREAK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self._SKIP and self.skip > 0:
            self.skip -= 1

    def handle_data(self, data):
        if self.skip == 0:
            t = data.strip()
            if t:
                self.parts.append(t + " ")


def _html_to_text(html: str) -> str:
    p = _TextExtractor()
    try:
        p.feed(html)
    except Exception:
        return ""
    text = "".join(p.parts)
    text = _re.sub(r"[ \t]+", " ", text)
    text = _re.sub(r"\n\s*\n+", "\n", text)
    return text.strip()


def _safe_name(name: str) -> str:
    return _re.sub(r"[^A-Za-z0-9_.-]", "_", name)


def _update_manifest(cache: Path, entry: dict) -> None:
    mpath = cache / "manifest.json"
    data = {}
    if mpath.exists():
        try:
            data = _json.loads(mpath.read_text(encoding="utf-8"))
        except Exception:
            data = {}
    data[entry["name"]] = entry
    mpath.write_text(_json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def fetch_and_cache_doc(
    url: str, name: str, cache_dir: str = DEFAULT_DOCS_CACHE,
    *, refresh: bool = False, window: int = 4500,
) -> Optional[str]:
    """Return a focused text excerpt of `url`'s doc, crawling once then reusing local.

    Layout in `cache_dir`:  <name>.txt (reused excerpt) + <name>.html (raw, reproducible)
    + manifest.json (url / fetched_at / sha of each). If the local .txt exists and
    `refresh` is False, no network call is made.
    """
    cache = Path(cache_dir)
    base = _safe_name(name)
    txt = cache / f"{base}.txt"
    raw = cache / f"{base}.html"
    if txt.exists() and not refresh:
        return txt.read_text(encoding="utf-8")
    try:
        req = _urlreq.Request(url, headers={"User-Agent": "clawgap-sinkdoc/1.0"})
        with _urlreq.urlopen(req, timeout=30) as r:  # noqa: S310 (trusted doc hosts)
            html = r.read().decode("utf-8", "ignore")
    except Exception:
        return None  # offline / unreachable -> caller falls back to introspection
    cache.mkdir(parents=True, exist_ok=True)
    text = _html_to_text(html)
    anchor = url.split("#", 1)[1] if "#" in url else None
    excerpt = text[:window]
    if anchor:
        key = anchor.split(".")[-1] if "." in anchor else anchor
        idx = text.find(anchor)
        if idx < 0 and key:
            idx = text.find(key)
        if idx > 0:
            excerpt = text[max(0, idx - 200): idx + window]
    raw.write_text(html, encoding="utf-8")
    txt.write_text(excerpt, encoding="utf-8")
    import hashlib
    _update_manifest(cache, {
        "name": base, "url": url,
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sha256": hashlib.sha256(html.encode("utf-8")).hexdigest(),
        "text_file": txt.name, "html_file": raw.name, "chars": len(excerpt),
    })
    return excerpt


def web_doc(import_path: Optional[str], cache_dir: str = DEFAULT_DOCS_CACHE,
            *, refresh: bool = False) -> Optional[str]:
    """Cached official-doc excerpt for an API (via DOC_URLS), or None if no URL."""
    if not import_path:
        return None
    url = DOC_URLS.get(import_path)
    if not url:
        return None
    return fetch_and_cache_doc(url, import_path, cache_dir, refresh=refresh)


def crawl_all(cache_dir: str = DEFAULT_DOCS_CACHE, *, refresh: bool = False) -> dict:
    """Crawl every DOC_URLS entry into the local snapshot; return {name: ok/bool}."""
    out: dict[str, bool] = {}
    for import_path in DOC_URLS:
        out[import_path] = fetch_and_cache_doc(
            DOC_URLS[import_path], import_path, cache_dir, refresh=refresh
        ) is not None
    return out
