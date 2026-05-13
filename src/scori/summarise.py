"""LLM changelog summary — tries Ollama, then Claude, then OpenAI."""

from __future__ import annotations

import os

import requests

_TIMEOUT = 30
_OLLAMA_URL = "http://localhost:11434/api/generate"
_CLAUDE_URL = "https://api.anthropic.com/v1/messages"
_OPENAI_URL = "https://api.openai.com/v1/chat/completions"

_OLLAMA_MODEL = "llama3.2"
_CLAUDE_MODEL = "claude-haiku-4-5-20251001"
_OPENAI_MODEL = "gpt-4o-mini"


def _make_prompt(name: str, current: str, latest: str, text: str) -> str:
    return (
        "You are a senior Python developer. Summarize this dependency update in "
        "exactly 1 sentence (max 120 chars): what changes for developers and any "
        "migration needed.\n"
        f"Package: {name}, {current} → {latest}\n"
        "Release notes:\n"
        f"{text[:3000]}"
    )


def _try_ollama(prompt: str) -> str | None:
    try:
        resp = requests.post(
            _OLLAMA_URL,
            json={"model": _OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return str(resp.json().get("response", "")).strip() or None
    except (requests.ConnectionError, requests.Timeout):
        return None
    except Exception:
        return None


def _try_claude(prompt: str) -> str | None:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return None
    try:
        resp = requests.post(
            _CLAUDE_URL,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": _CLAUDE_MODEL,
                "max_tokens": 200,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        content = resp.json().get("content", [])
        if content and isinstance(content, list):
            return str(content[0].get("text", "")).strip() or None
        return None
    except Exception:
        return None


def _try_openai(prompt: str) -> str | None:
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        return None
    try:
        resp = requests.post(
            _OPENAI_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": _OPENAI_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 200,
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        choices = resp.json().get("choices", [])
        if choices:
            return str(choices[0].get("message", {}).get("content", "")).strip() or None
        return None
    except Exception:
        return None


def summarise(name: str, current: str, latest: str, text: str) -> str:
    """Return a 1-sentence summary of the dependency update, or "" on failure.

    Tries providers in order: Ollama → Claude → OpenAI.
    """
    prompt = _make_prompt(name, current, latest, text)

    result = _try_ollama(prompt)
    if result:
        return result

    result = _try_claude(prompt)
    if result:
        return result

    result = _try_openai(prompt)
    if result:
        return result

    return ""
