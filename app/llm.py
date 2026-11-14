"""Ollama client (Llama 3.2) with a graceful offline mode.

Uses ``langchain_ollama.ChatOllama`` when the local Ollama server answers.
When it does not, every caller falls back to deterministic behaviour, so the
project runs on a laptop with nothing installed.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache

import httpx

from app.config import Settings, get_settings

try:
    from langchain_ollama import ChatOllama
except Exception:  # pragma: no cover - optional dependency at import time
    ChatOllama = None  # type: ignore[assignment]


@lru_cache(maxsize=8)
def _probe(base_url: str, timeout: float = 1.5) -> bool:
    try:
        response = httpx.get(f"{base_url.rstrip('/')}/api/tags", timeout=timeout)
        return response.status_code == 200
    except Exception:
        return False


def extract_json(text: str | None) -> dict | None:
    """Pull the first JSON object out of a model reply."""
    if not text:
        return None
    cleaned = text.strip().strip("`")
    cleaned = re.sub(r"^json\s*", "", cleaned, flags=re.I)
    try:
        parsed = json.loads(cleaned)
        return parsed if isinstance(parsed, dict) else None
    except (TypeError, ValueError):
        pass
    match = re.search(r"\{.*\}", cleaned, re.S)
    if not match:
        return None
    try:
        parsed = json.loads(match.group(0))
        return parsed if isinstance(parsed, dict) else None
    except (TypeError, ValueError):
        return None


class LLMClient:
    """Thin wrapper that never raises because of a missing model."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self._model = None
        self._failed = False

    @property
    def mode(self) -> str:
        return self.settings.llm_mode

    def available(self) -> bool:
        if self._failed or ChatOllama is None:
            return False
        if self.mode == "mock":
            return False
        if self.mode == "ollama":
            return True
        return _probe(self.settings.ollama_base_url)

    def _build(self):
        if self._model is not None:
            return self._model
        kwargs = dict(
            model=self.settings.ollama_model,
            base_url=self.settings.ollama_base_url,
            temperature=0.0,
            num_predict=512,
        )
        try:
            self._model = ChatOllama(**kwargs)
        except TypeError:
            try:
                self._model = ChatOllama(**kwargs, client_kwargs={"timeout": self.settings.ollama_timeout})
            except Exception:
                self._failed = True
                return None
        except Exception:
            self._failed = True
            return None
        return self._model

    def complete(self, system: str, prompt: str) -> str | None:
        if not self.available():
            return None
        model = self._build()
        if model is None:
            return None
        try:
            message = model.invoke([("system", system), ("human", prompt)])
        except Exception:
            self._failed = True
            return None
        content = getattr(message, "content", "")
        if isinstance(content, list):
            content = "".join(part.get("text", "") if isinstance(part, dict) else str(part) for part in content)
        return str(content)

    def complete_json(self, system: str, prompt: str) -> dict | None:
        return extract_json(self.complete(system, prompt))

    def describe(self) -> str:
        if self.available():
            return f"ollama:{self.settings.ollama_model}"
        return "heuristic (Ollama unavailable)"
