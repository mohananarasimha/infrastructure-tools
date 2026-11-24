"""Lightweight stdlib asyncio OpenAI-compatible SSE mock server for tests and demos."""

from __future__ import annotations

import asyncio
import contextlib
import json
import random
import socket
from types import TracebackType
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

ALLOWED_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})


class MockServerConfig(BaseModel):
    """Configuration for the local OpenAI-compatible SSE mock server."""

    model_config = ConfigDict(frozen=True)

    host: str = "127.0.0.1"
    port: int = Field(default=0, ge=0, le=65535)
    ttft_ms: float = Field(default=10.0, ge=0.0)
    itl_ms: float = Field(default=5.0, ge=0.0)
    tokens_per_response: int = Field(default=8, ge=1)
    stall_ms: float = Field(default=0.0, ge=0.0)
    stall_at_token: int = Field(default=3, ge=1)
    error_429_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    error_503_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    truncate_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    malformed_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    emit_usage: bool = True
    seed: int = 42

    @field_validator("host")
    @classmethod
    def _validate_loopback(cls, value: str) -> str:
        if value not in ALLOWED_LOOPBACK_HOSTS:
            allowed = ", ".join(sorted(ALLOWED_LOOPBACK_HOSTS))
            raise ValueError(
                f"Mock server may only bind to loopback ({allowed}), got '{value}'."
            )
        return value


class MockInferenceServer:
    """In-process asyncio HTTP/1.1 mock server implementing OpenAI SSE chat completions."""

    def __init__(self, config: MockServerConfig | None = None) -> None:
        self.config = config or MockServerConfig()
        self._rng = random.Random(self.config.seed)  # noqa: S311
        self._server: asyncio.AbstractServer | None = None
        self._port: int = self.config.port
        self._req_counter = 0

    @property
    def port(self) -> int:
        return self._port

    @property
    def base_url(self) -> str:
        return f"http://{self.config.host}:{self._port}"

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.config.host,
            port=self.config.port,
        )
        sockets = self._server.sockets
        if sockets:
            self._port = int(sockets[0].getsockname()[1])

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def __aenter__(self) -> MockInferenceServer:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.stop()

    def _next_outcome(self) -> str:
        roll = self._rng.random()
        threshold = self.config.error_429_rate
        if roll < threshold:
            return "429"
        threshold += self.config.error_503_rate
        if roll < threshold:
            return "503"
        threshold += self.config.truncate_rate
        if roll < threshold:
            return "truncate"
        threshold += self.config.malformed_rate
        if roll < threshold:
            return "malformed"
        return "ok"

    async def _send_json_response(
        self,
        writer: asyncio.StreamWriter,
        status_code: int,
        reason: str,
        payload: dict[str, Any],
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        headers = (
            f"HTTP/1.1 {status_code} {reason}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")
        writer.write(headers + body)
        await writer.drain()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        sock = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        try:
            raw_head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
        except (
            asyncio.IncompleteReadError,
            TimeoutError,
            ConnectionError,
            asyncio.LimitOverrunError,
        ):
            writer.close()
            return

        head_text = raw_head.decode("iso-8859-1", errors="replace")
        lines = head_text.split("\r\n")
        if not lines:
            writer.close()
            return

        parts = lines[0].split(" ")
        if len(parts) < 2:
            writer.close()
            return
        method, path = parts[0], parts[1].split("?", 1)[0]

        content_length = 0
        for header_line in lines[1:]:
            if ":" in header_line:
                name, val = header_line.split(":", 1)
                if name.strip().lower() == "content-length":
                    try:
                        content_length = max(0, int(val.strip()))
                    except ValueError:
                        content_length = 0

        body_bytes = b""
        if content_length > 0:
            try:
                body_bytes = await asyncio.wait_for(
                    reader.readexactly(content_length), timeout=5.0
                )
            except (asyncio.IncompleteReadError, TimeoutError, ConnectionError):
                writer.close()
                return

        try:
            if method == "GET" and path == "/health":
                await self._send_json_response(writer, 200, "OK", {"status": "ok"})
                return

            if method != "POST" or not path.endswith("/chat/completions"):
                await self._send_json_response(
                    writer, 404, "Not Found", {"error": {"message": "endpoint not found"}}
                )
                return

            req_body: dict[str, Any] = {}
            if body_bytes:
                try:
                    loaded = json.loads(body_bytes.decode("utf-8"))
                    if isinstance(loaded, dict):
                        req_body = loaded
                except json.JSONDecodeError:
                    await self._send_json_response(
                        writer, 400, "Bad Request", {"error": {"message": "invalid json"}}
                    )
                    return

            self._req_counter += 1
            req_num = self._req_counter
            outcome = self._next_outcome()

            if outcome == "429":
                await self._send_json_response(
                    writer,
                    429,
                    "Too Many Requests",
                    {"error": {"message": "rate limit exceeded", "type": "rate_limit_error"}},
                )
                return

            if outcome == "503":
                await self._send_json_response(
                    writer,
                    503,
                    "Service Unavailable",
                    {"error": {"message": "inference engine overloaded", "type": "server_error"}},
                )
                return

            model = str(req_body.get("model") or "mock-model")
            max_tokens_raw = req_body.get("max_tokens")
            requested_max = (
                int(max_tokens_raw)
                if isinstance(max_tokens_raw, int) and max_tokens_raw >= 1
                else self.config.tokens_per_response
            )
            num_tokens = min(self.config.tokens_per_response, requested_max)
            stream_opts = req_body.get("stream_options")
            wants_usage = (
                isinstance(stream_opts, dict) and stream_opts.get("include_usage") is True
            )

            sse_headers = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/event-stream\r\n"
                "Cache-Control: no-cache\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            writer.write(sse_headers)
            await writer.drain()

            # Role-only framing chunk (empty content) like real OpenAI/vLLM servers emit.
            role_chunk = {
                "id": f"chatcmpl-mock-{req_num}",
                "object": "chat.completion.chunk",
                "model": model,
                "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
            }
            writer.write(f"data: {json.dumps(role_chunk)}\n\n".encode())
            await writer.drain()

            if self.config.ttft_ms > 0:
                await asyncio.sleep(self.config.ttft_ms / 1000.0)

            if outcome == "malformed":
                writer.write(b"data: {malformed-json-chunk\n\n")
                await writer.drain()
                return

            emit_count = max(1, num_tokens // 2) if outcome == "truncate" else num_tokens
            for idx in range(emit_count):
                if idx > 0:
                    delay_ms = self.config.itl_ms
                    if self.config.stall_ms > 0 and idx == self.config.stall_at_token:
                        delay_ms += self.config.stall_ms
                    if delay_ms > 0:
                        await asyncio.sleep(delay_ms / 1000.0)

                chunk = {
                    "id": f"chatcmpl-mock-{req_num}",
                    "object": "chat.completion.chunk",
                    "model": model,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"content": f"tok{idx} "},
                            "finish_reason": None,
                        }
                    ],
                }
                writer.write(f"data: {json.dumps(chunk)}\n\n".encode())
                await writer.drain()

            if outcome == "truncate":
                # Deliberately close stream without finish_reason or [DONE].
                return

            stop_chunk = {
                "id": f"chatcmpl-mock-{req_num}",
                "object": "chat.completion.chunk",
                "model": model,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            }
            writer.write(f"data: {json.dumps(stop_chunk)}\n\n".encode())
            await writer.drain()

            if self.config.emit_usage and wants_usage:
                usage_chunk = {
                    "id": f"chatcmpl-mock-{req_num}",
                    "object": "chat.completion.chunk",
                    "model": model,
                    "choices": [],
                    "usage": {
                        "prompt_tokens": 12,
                        "completion_tokens": num_tokens,
                        "total_tokens": 12 + num_tokens,
                    },
                }
                writer.write(f"data: {json.dumps(usage_chunk)}\n\n".encode())
                await writer.drain()

            writer.write(b"data: [DONE]\n\n")
            await writer.drain()
        except (ConnectionError, BrokenPipeError, asyncio.CancelledError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await writer.wait_closed()
