"""Pluggable LLM provider layer.

Targets any OpenAI-compatible chat completions endpoint. Designed for free-tier
providers (OpenRouter :free models, local llama.cpp / LM Studio, free gateways):
- env-driven config, no hardcoded keys
- fallback model chain when a model is unavailable or rate-limited
- lenient structured output: prompts demand JSON; we extract and validate
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from openai import OpenAI

from ..errors import ProviderError

GOOGLE_BASE_MARKER = "generativelanguage.googleapis.com"

OPENROUTER_CHAIN = [
    "deepseek/deepseek-chat-v3-0324:free",
    "qwen/qwen3-coder:free",
    "meta-llama/llama-3.3-70b-instruct:free",
]

GOOGLE_CHAIN = [
    "gemini-3.8-flash",
    "gemini-3.5-flash-lite",
]


def load_env_file(path: str | Path = ".env") -> None:
    """Load KEY=VALUE pairs into os.environ (existing env vars win)."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        os.environ.setdefault(key.strip(), val.strip())


def _models_from_env() -> list[str]:
    base = os.environ.get("AGENT_LLM_BASE_URL", "")
    default_chain = GOOGLE_CHAIN if GOOGLE_BASE_MARKER in base else OPENROUTER_CHAIN
    primary = os.environ.get("AGENT_LLM_MODEL")
    chain = list(default_chain) if primary is None else [primary]
    chain += [m for m in default_chain if m not in chain]
    return chain


class LLMProvider:
    def __init__(self) -> None:
        load_env_file()
        self.base_url = os.environ.get(
            "AGENT_LLM_BASE_URL",
            "https://generativelanguage.googleapis.com/v1beta/openai/"
            if os.environ.get("AGENT_LLM_API_KEY", "").startswith("AQ.")
            else "https://openrouter.ai/api/v1",
        )
        self.api_key = os.environ.get("AGENT_LLM_API_KEY", "")
        self.models = _models_from_env()
        self._client = OpenAI(base_url=self.base_url, api_key=self.api_key or "not-set")

    def chat(self, system: str, user: str, temperature: float = 0.2) -> str:
        """One completion with model fallback. Raises ProviderError if all fail."""
        errors = []
        for model in self.models:
            try:
                resp = self._client.chat.completions.create(
                    model=model,
                    messages=[{"role": "system", "content": system},
                              {"role": "user", "content": user}],
                    temperature=temperature,
                    max_tokens=2000,
                )
                return resp.choices[0].message.content or ""
            except Exception as exc:  # noqa: BLE001 — any provider failure -> next model
                errors.append(f"{model}: {exc}")
                time.sleep(1)
        raise ProviderError("all LLM models failed:\n" + "\n".join(errors))


def extract_json(text: str) -> dict | list:
    """Pull the first JSON object/array out of an LLM reply (lenient)."""
    fenced = re.search(r"```(?:json)?\s*(.+?)```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        if start == -1:
            continue
        depth = 0
        for i in range(start, len(text)):
            if text[i] == opener:
                depth += 1
            elif text[i] == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        break
    raise ProviderError(f"no valid JSON in reply:\n{text[:400]}")
