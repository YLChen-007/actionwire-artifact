"""Drive AstrBot's real dashboard/OpenAPI chat boundary."""

from __future__ import annotations

import json
import os
import urllib.request


BASE_URL = "http://127.0.0.1:18080"


def post(path: str, payload: object, token: str | None = None) -> dict:
    request = urllib.request.Request(
        BASE_URL + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=30) as response:
        value = json.loads(response.read())
    if not isinstance(value, dict):
        raise RuntimeError("AstrBot probe returned a non-object response")
    return value


def require_ok(value: dict, label: str) -> dict:
    if value.get("code") not in {None, 0, 200} or value.get("status") == "error":
        raise RuntimeError(f"{label}: {value}")
    return value


login = require_ok(
    post(
        "/api/auth/login",
        {"username": "astrbot", "password": "ClawGapProbe1"},
    ),
    "dashboard login",
)
dashboard_token = str(login["data"]["token"])
created = require_ok(
    post(
        "/api/apikey/create",
        {"name": "clawgap-environment-probe", "scopes": ["chat"]},
        dashboard_token,
    ),
    "API-key creation",
)
open_api_key = str(created["data"]["api_key"])
chat_request = urllib.request.Request(
    BASE_URL + "/api/v1/chat",
    data=json.dumps({"username": "clawgap", "message": "environment probe"}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
chat_request.add_header("Authorization", f"Bearer {open_api_key}")
with urllib.request.urlopen(chat_request, timeout=30) as response:
    response.read(4096)
if os.environ.get("CLAWGAP_DEBUG"):
    print(json.dumps(chat, sort_keys=True))
