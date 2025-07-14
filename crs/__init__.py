# type: ignore
from typing import Any, Callable
import asyncio
import functools
import gc
import hashlib
import os
import sys
import threading
import time
import traceback
import warnings

if not ((sys.version_info[:2] == (3, 12) and sys.version_info[2] <= 10)
        or (sys.version_info[:2] == (3, 13) and sys.version_info[2] <= 4)):
    with open(asyncio.selector_events.__file__, "rb") as f:
        selector_events_hash = hashlib.file_digest(f, "sha256").hexdigest()
    if selector_events_hash != "c599c1cb03b45b931eef8c0ba1c8122aa456e0f3d24fd813f12ab70cd6f52636":
        raise RuntimeError("unsupported Python version")
# monkeypatch for https://github.com/python/cpython/issues/130141
cls = asyncio.selector_events._SelectorTransport
@functools.wraps(cls.__del__)
def __del__(self, _warn=warnings.warn):
    if self._sock is not None:
        _warn(f"unclosed transport {self!r}", ResourceWarning, source=self)
        self._closing = True
        self._buffer.clear()
        self._sock.close()
cls.__del__ = __del__

# monkeypatch httpx to Rust implementation
import crs_rust
import httpx
httpx_AsyncClient = httpx.AsyncClient

class RustAsyncClient:
    def __init__(self, **kwargs):
        self.httpx_client = httpx_AsyncClient(**kwargs)
        self.rust_client = crs_rust.http.Client()

    @property
    def is_closed(self) -> None:
        return self.rust_client.is_closed

    async def aclose(self) -> None:
        self.rust_client.close()

    def build_request(self, *args, **kwargs) -> httpx.Request:
        return self.httpx_client.build_request(*args, **kwargs)

    async def send(
        self,
        request: httpx.Request,
        *,
        stream: bool = False,
        auth: httpx._types.AuthTypes | httpx._client.UseClientDefault | None = httpx.USE_CLIENT_DEFAULT,
        follow_redirects: bool | httpx._client.UseClientDefault = httpx.USE_CLIENT_DEFAULT,
    ) -> httpx.Response:
        if auth is httpx.USE_CLIENT_DEFAULT:
            auth = self.httpx_client.auth
        if follow_redirects is httpx.USE_CLIENT_DEFAULT:
            follow_redirects = self.httpx_client.follow_redirects

        assert not auth
        assert not stream

        # NOTE: reqwest follows 10 redirects by default
        resp = await self.rust_client.request(request)
        return resp

httpx.AsyncClient = RustAsyncClient

# monkeypatch traceback.format_exc because litellm calls it internally
@functools.wraps(traceback.format_exc)
def format_exc(limit: int | None=None, chain: bool=True) -> str:
    exctype, exc, tb = sys.exc_info()
    chunks: list[str] = []
    if tb:
        chunks.append("Traceback:")
    while tb:
        frame = tb.tb_frame
        code = frame.f_code
        chunks.append(f"  {code.co_filename}:{frame.f_lineno} in {code.co_name}")
        tb = tb.tb_next
    chunks.append(f"{exctype.__name__}: {exc}")
    return "\n".join(chunks)
traceback.format_exc = format_exc

def recovery_thread():
    pid = os.getpid()
    path = f"/tmp/recovery/{pid}.txt"

    def get_objects(predicate: Callable[[Any], bool]) -> list[Any]:
        def try_predicate(obj: Any) -> bool:
            try:
                return predicate(obj)
            except Exception:
                return False

        return [obj for obj in gc.get_objects()
                if try_predicate(obj)]

    def recovery_loop():
        _globals = {**globals(), "get_objects": get_objects}
        while True:
            time.sleep(3)
            try:
                try:
                    with open(path) as f:
                        data = f.read()
                except FileNotFoundError:
                    continue

                try:
                    os.remove(path)
                except OSError:
                    pass

                exec(data, _globals)

            except Exception:
                traceback.print_exc()

    thread = threading.Thread(target=recovery_loop, daemon=True, name="recovery-thread")
    thread.start()

recovery_thread()
