"""Install ClawGap runtime instrumentation in an opted-in target process."""

from __future__ import annotations

import os
from pathlib import Path


try:
    if os.getenv("CLAWGAP_AGENT_INSTRUMENTATION_PATH", "").strip():
        from src.runtime_validation.inject.agent_sitecustomize import (
            install_from_environment as install_agent_runtime,
        )

        install_agent_runtime()
    elif os.getenv("CLAWGAP_PROPAGATION_CASE_PATH", "").strip():
        from src.runtime_validation.propagation_instrumentation import (
            install_from_environment,
        )
        install_from_environment()
    else:
        from src.runtime_validation.instrumentation import (
            install_from_environment,
        )

        install_from_environment()
except Exception as exc:  # pragma: no cover - exercised through subprocess tests
    error_path = os.getenv("CLAWGAP_RUNTIME_ERROR_PATH", "").strip()
    if error_path:
        try:
            path = Path(error_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
        except Exception:
            pass
