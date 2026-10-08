"""Optional WebSocket endpoint for live dashboard events."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Awaitable, Callable
from typing import Any

from .events import EventHub


class WebSocketServer:
    """Serve EventHub messages with bounded, stale-connection-aware clients.

    The ``websockets`` package is optional so the desktop application and all
    standard-library backend tests continue to work without it installed.
    """

    def __init__(
        self,
        hub: EventHub,
        host: str = "127.0.0.1",
        port: int = 8765,
        ping_interval: float = 20.0,
        ping_timeout: float = 20.0,
    ) -> None:
        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if ping_interval <= 0 or ping_timeout <= 0:
            raise ValueError("ping settings must be greater than zero")
        self.hub = hub
        self.host = host
        self.port = port
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: Any = None
        self._ready = threading.Event()
        self._startup_error: BaseException | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and self._startup_error is None

    def start(self) -> bool:
        if self._thread is not None and self._thread.is_alive():
            return False
        self._ready.clear()
        self._startup_error = None
        self._thread = threading.Thread(target=self._run, daemon=True, name="websocket-server")
        self._thread.start()
        self._ready.wait(timeout=5)
        if self._startup_error is not None:
            raise RuntimeError("WebSocket server could not start") from self._startup_error
        return True

    def stop(self, timeout: float = 5.0) -> None:
        loop = self._loop
        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(loop.stop)
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=max(0.0, timeout))

    def _run(self) -> None:
        try:
            import websockets
        except ImportError as exc:
            self._startup_error = exc
            self._ready.set()
            return
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._server = self._loop.run_until_complete(
                websockets.serve(
                    self._handler,
                    self.host,
                    self.port,
                    ping_interval=self.ping_interval,
                    ping_timeout=self.ping_timeout,
                    max_size=1_048_576,
                )
            )
            self._ready.set()
            self._loop.run_forever()
        except BaseException as exc:
            self._startup_error = exc
            self._ready.set()
        finally:
            if self._server is not None:
                self._server.close()
                self._loop.run_until_complete(self._server.wait_closed())
            self._loop.close()
            self._loop = None

    async def _handler(self, websocket: Any, _path: str | None = None) -> None:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=100)

        def enqueue(message: str) -> None:
            def put() -> None:
                if queue.full():
                    try:
                        queue.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                queue.put_nowait(message)

            if not loop.is_closed():
                loop.call_soon_threadsafe(put)

        unsubscribe = self.hub.subscribe(enqueue)
        try:
            while True:
                await websocket.send(await queue.get())
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            unsubscribe()

