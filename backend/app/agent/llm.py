"""OpenRouter access for Saqr: a lazy client factory and one ``chat()`` call.

Mirrors the contract ``backend/app/rag/packet_qa.py`` established for ``/ask``:

* importing this module never fails and never touches the network -- the client
  is built on first use, and a missing key raises the typed
  :class:`SaqrUnavailable` so the router can answer a clean 503;
* configuration is read from ``backend.app.config.settings``, so ``.env`` is the
  only place credentials live.

Unlike the RAG client this one is used with ``tools=``.  ``chat()`` returns the
whole assistant *message* rather than its text, because the loop needs
``message.tool_calls`` as well as ``message.content``.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Iterator, List, Optional, Sequence

from backend.app.config import settings

logger = logging.getLogger(__name__)

__all__ = [
    "SaqrUnavailable", "get_client", "model_name", "chat", "chat_stream", "reset_client",
]


class SaqrUnavailable(RuntimeError):
    """Saqr cannot serve requests (no API key, no model, or the switch is off).

    ``/agent/ask`` turns this into a clean HTTP 503, with the same message
    ``/ask`` returns today when ``OPENROUTER_API_KEY`` is missing.
    """


_client: Any = None


def reset_client() -> None:
    """Drop the cached client.  Used by tests and after a configuration change."""
    global _client
    _client = None


def model_name() -> str:
    """The model id to call: ``SAQR_MODEL``, else ``GEN_MODEL``."""
    model = settings.saqr_model
    if not model:
        raise SaqrUnavailable(
            "No model is configured; set SAQR_MODEL (or GEN_MODEL) in .env."
        )
    return model


def get_client() -> Any:
    """Build (once) and return the OpenRouter client.

    Raises :class:`SaqrUnavailable` when no key is configured or the ``openai``
    package cannot be imported.
    """
    global _client
    if _client is not None:
        return _client

    api_key = settings.OPENROUTER_API_KEY.strip()
    if not api_key:
        # Deliberately the same sentence /ask answers with, so a 503 from either
        # route points at the same missing line in .env.
        raise SaqrUnavailable(
            "OPENROUTER_API_KEY is not configured; the assistant is disabled."
        )

    try:
        from openai import OpenAI  # OpenRouter speaks the OpenAI wire protocol
    except Exception as exc:  # pragma: no cover - packaging problem
        raise SaqrUnavailable(f"The openai package is not installed: {exc}") from exc

    headers = {
        "HTTP-Referer": settings.OPENROUTER_SITE_URL,
        "X-Title": settings.OPENROUTER_APP_NAME,
    }
    _client = OpenAI(
        api_key=api_key,
        base_url=settings.OPENROUTER_BASE_URL,
        default_headers=headers,
    )
    logger.info(
        "Saqr OpenRouter client initialised (model=%s, base_url=%s)",
        settings.saqr_model, settings.OPENROUTER_BASE_URL,
    )
    return _client


def chat(
    messages: Sequence[Dict[str, Any]],
    *,
    tools: Optional[Sequence[Dict[str, Any]]] = None,
    tool_choice: Optional[str] = None,
    temperature: Optional[float] = None,
    model: Optional[str] = None,
) -> Any:
    """One chat completion.  Returns the assistant *message* object.

    ``tools`` / ``tool_choice`` are passed straight through when supplied.  The
    caller reads ``.content`` for prose and ``.tool_calls`` for requested calls.
    """
    client = get_client()
    kwargs: Dict[str, Any] = {
        "model": model or model_name(),
        "temperature": settings.SAQR_TEMPERATURE if temperature is None else float(temperature),
        "messages": list(messages),
    }
    if tools:
        kwargs["tools"] = list(tools)
        if tool_choice is not None:
            kwargs["tool_choice"] = tool_choice

    response = client.chat.completions.create(**kwargs)
    choices: List[Any] = list(getattr(response, "choices", None) or [])
    if not choices:
        raise SaqrUnavailable("The model returned no choices; the request was refused upstream.")
    return choices[0].message


def chat_stream(
    messages: Sequence[Dict[str, Any]],
    *,
    tools: Optional[Sequence[Dict[str, Any]]] = None,
    tool_choice: Optional[str] = None,
    temperature: Optional[float] = None,
    model: Optional[str] = None,
) -> Iterator[str]:
    """Yield the assistant's text deltas, one chunk at a time.

    Deliberately **text only**.  Use this for the final composing turn, which is
    forced to ``tool_choice="none"`` and therefore cannot emit a tool call.

    Do not use it for a tool-selection turn: with ``stream=True`` the SDK
    delivers a tool call in fragments -- ``id`` and ``function.name`` arrive only
    on the first chunk of each call, and ``function.arguments`` arrives as a
    partial JSON string spread over many chunks, indexed by
    ``delta.tool_calls[i].index``.  Reassembling that correctly is fiddly and
    getting it subtly wrong produces calls with truncated arguments.  The
    ``status`` / ``tool_call`` / ``tool_result`` events already give the UI its
    motion during those turns, so there is nothing to buy by streaming them.

    This is a blocking generator (the SDK's stream is synchronous); the caller
    drives it on a worker thread.
    """
    client = get_client()
    kwargs: Dict[str, Any] = {
        "model": model or model_name(),
        "temperature": settings.SAQR_TEMPERATURE if temperature is None else float(temperature),
        "messages": list(messages),
        "stream": True,
    }
    if tools:
        kwargs["tools"] = list(tools)
        if tool_choice is not None:
            kwargs["tool_choice"] = tool_choice

    for chunk in client.chat.completions.create(**kwargs):
        choices = list(getattr(chunk, "choices", None) or [])
        if not choices:
            # OpenRouter interleaves usage-only and comment chunks; skip them.
            continue
        delta = getattr(choices[0], "delta", None)
        text = getattr(delta, "content", None) if delta is not None else None
        if text:
            yield text
