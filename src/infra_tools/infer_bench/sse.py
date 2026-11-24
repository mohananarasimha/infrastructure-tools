"""Pure SSE line parser for OpenAI-compatible / vLLM chat completion streams."""

from __future__ import annotations

import json
from dataclasses import dataclass


class SseParseError(Exception):
    """Raised when an SSE ``data:`` line contains malformed JSON or invalid shape."""


@dataclass(frozen=True)
class ParsedSseLine:
    """Normalized representation of one parsed SSE ``data:`` payload."""

    is_done: bool = False
    has_content: bool = False
    content: str = ""
    completion_tokens: int | None = None


def parse_sse_line(raw_line: str) -> ParsedSseLine | None:
    """Parse one raw SSE line.

    Returns ``None`` for blank lines, SSE comments, or non-``data:`` control fields.
    Raises ``SseParseError`` for malformed JSON or non-object ``data:`` payloads.
    """
    line = raw_line.rstrip("\r\n")
    if not line or line.startswith(":"):
        return None

    if not line.startswith("data:"):
        return None

    payload = line[5:]
    if payload.startswith(" "):
        payload = payload[1:]
    payload = payload.strip()

    if not payload:
        return None

    if payload == "[DONE]":
        return ParsedSseLine(is_done=True)

    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SseParseError(f"Malformed JSON in SSE data chunk: {exc.msg}") from exc

    if not isinstance(parsed, dict):
        raise SseParseError(
            f"Expected JSON object in SSE data chunk, got {type(parsed).__name__}."
        )

    completion_tokens: int | None = None
    usage = parsed.get("usage")
    if isinstance(usage, dict):
        raw_completion = usage.get("completion_tokens")
        if isinstance(raw_completion, int) and not isinstance(raw_completion, bool):
            completion_tokens = raw_completion

    content = ""
    choices = parsed.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            delta = first.get("delta")
            if isinstance(delta, dict):
                raw_content = delta.get("content")
                if isinstance(raw_content, str) and raw_content != "":
                    content = raw_content

    return ParsedSseLine(
        is_done=False,
        has_content=bool(content),
        content=content,
        completion_tokens=completion_tokens,
    )
