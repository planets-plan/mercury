import os
import re
import sys
import ssl
import http
import socket
import signal
import logging
import inspect
import asyncio
import platform
import functools
import threading

from types import FrameType

from mercury.type import (
    cast,
    Set,
    List,
    Type,
    Tuple,
    Union,
    Literal,
    Optional,
    Sequence,
    Callable,
    TYPE_CHECKING,
)
from mercury.utils.importer import import_app_from_string, ImportFromStringError
from mercury.utils.terminal_color import colorize

from .protocol import HttpProtocol
from .lifespan import LifespanOn, LifespanOff
from .middleware import WSGIMiddleware, ASGI2Middleware, DebugMiddleware

if TYPE_CHECKING:
    from mercury.core.server.lifespan import Lifespan
    from mercury.core.server.protocol import HttpProtocol
    from mercury.type import ASGIApplication, ServerConfigOptions
    CustomProtocol = Union[HttpProtocol]


HANDLED_SIGNALS = (
    signal.SIGINT,  # Unix signal 2. Sent by Ctrl+C.
    signal.SIGTERM,  # Unix signal 15. Sent by `kill <pid>`.
)


def _create_ssl_context(
    certfile: Union[str, os.PathLike],
    keyfile: Optional[Union[str, os.PathLike]],
    password: Optional[str],
    ssl_version: int,
    cert_reqs: int,
    ca_certs: Optional[Union[str, os.PathLike]],
    ciphers: Optional[str]
) -> ssl.SSLContext:
    """ create ssl context by setting """
    context = ssl.SSLContext(ssl_version)
    get_password = (lambda: password) if password else None
    context.load_cert_chain(certfile, keyfile, get_password)
    context.verify_mode = ssl.VerifyMode(cert_reqs)
    if ca_certs:
        context.load_verify_locations(ca_certs)
    if ciphers:
        context.set_ciphers(ciphers)
    return context


def _asyncio_event_loop_init(need_subprocess: bool = False) -> None:
    try:
        import uvloop
    except ImportError:
        if sys.version_info >= (3, 8) and sys.platform == "win32" and need_subprocess:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    else:
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


class Server:
    @property
    def asgi_version(self) -> Literal["2.0", "3.0"]:
        return self._asgi_version

    def __init__(self,  **options: "ServerConfigOptions") -> None:
        # base options
        self.app: Optional[Union["ASGIApplication", "Callable", str]] = options.get("app")
        self.host: Optional[str] = options.get("host", None)
        self.port: Optional[int] = options.get("port", None)
        self.uds: Optional[str] = options.get("uds", None)
        self.fd: Optional[str] = options.get("fd", None)
        self.debug: bool = options.get("debug", False)
        self.root_path: str = options.get("root_path", "")
        self.worker_number: int = options.get("worker_number", 1)
        self.specification: str = options.get("specification", "auto")

        # reload options
        self.reload: bool = options.get("reload", False)
        self.reload_dirs = None
        self.reload_delay = None
        self.reload_includes = None
        self.reload_excludes = None

        # ssl options
        self.ssl: Optional[ssl.SSLContext] = None
        self.ssl_keyfile: Optional[str] = None
        self.ssl_certfile: Optional[Union[str, os.PathLike]] = None
        self.ssl_keyfile_password: Optional[str] = None
        self.ssl_version: int = 0
        self.ssl_cert_reqs: int = 0
        self.ssl_ca_certs: Optional[str] = None
        self.ssl_ciphers: str = "TLSv1"

        # header options and attribute
        self.has_date_header: bool = options.get("date_header", False)
        self.has_proxy_header: bool = options.get("proxy_header", False)
        self.has_server_header: bool = options.get("server_header", False)
        self.headers: Optional[Tuple[str, str]] = options.get("headers", None)
        self.default_headers: List[Tuple[bytes, bytes]] = []
        self.encoded_headers: List[Tuple[bytes, bytes]] = []

        # attribute
        self.logger = logging.getLogger("mercury.server.access")
        self.error_logger = logging.getLogger("mercury.server.error")
        self.lifespan: Optional["Lifespan"] = None
        self.loaded_app: Optional[Callable] = None

        # server state
        self.servers: List[asyncio.AbstractServer] = []
        self.tasks: Set[asyncio.Task] = set()
        self.connections: Set["CustomProtocol"] = set()
        self.request_number: int = 0
        self._asgi_version: Optional[Literal["2.0", "3.0"]] = None

        # judge attribute
        self.force_exit: bool = False
        self.is_exited: bool = False
        self.is_started: bool = False
        self.should_exit: bool = False
        self.is_ssl: bool = bool(self.ssl_keyfile or self.ssl_certfile)
        self.is_loaded: bool = False
        self.is_windows: bool = platform.system().lower() == "windows"
        self.need_subprocess: bool = bool(self.reload or self.worker_number > 1)

    def load(self) -> None:
        # load event loop
        _asyncio_event_loop_init(self.need_subprocess)

        # load ssl
        if self.is_ssl:
            assert self.ssl_certfile
            self.ssl = _create_ssl_context(
                keyfile=self.ssl_keyfile,
                certfile=self.ssl_certfile,
                password=self.ssl_keyfile_password,
                ssl_version=self.ssl_version,
                cert_reqs=self.ssl_cert_reqs,
                ca_certs=self.ssl_ca_certs,
                ciphers=self.ssl_ciphers,
            )

        # load header
        self.encoded_headers = [
            (key.lower().encode("latin1"), value.encode("latin1"))
            for key, value in self.headers
        ]
        if b"server" not in dict(self.encoded_headers) and self.has_server_header:
            self.encoded_headers.insert(0, (b"server", b"server"))

        # load app
        try:
            self.loaded_app = import_app_from_string(self.app)
        except ImportFromStringError as e:
            self.logger.error(f"Error loading ASGI app. {e}")
            sys.exit(1)

        # load specification
        if self.specification != "wsgi":
            if inspect.isclass(self.loaded_app):
                use_asgi_3 = hasattr(self.loaded_app, "__await__")
            elif inspect.isfunction(self.loaded_app):
                use_asgi_3 = asyncio.iscoroutinefunction(self.loaded_app)
            else:
                call = getattr(self.loaded_app, "__call__", None)
                use_asgi_3 = asyncio.iscoroutinefunction(call)
            self.specification = "asgi3" if use_asgi_3 else "asgi2"

        if self.specification == "wsgi":
            self._asgi_version = "3.0"
            self.loaded_app = WSGIMiddleware(self.loaded_app)
        elif self.specification == "asgi2":
            self._asgi_version = "2.0"
            self.loaded_app = ASGI2Middleware(self.loaded_app)

        # load debug
        if self.debug:
            self.loaded_app = DebugMiddleware(self.loaded_app)

        # load lifespan
        if self.specification != "wsgi":
            self.lifespan = LifespanOff()
        else:
            self.lifespan = LifespanOn(self)

        # bind func to handle the signal
        self._install_signal_handlers()

        self.is_loaded = True

    def run(self, sockets: Optional[List[socket.socket]] = None) -> None:
        return asyncio.run(self.serve(sockets=sockets))

    async def serve(self, sockets: Optional[List[socket.socket]] = None) -> None:
        # start load func, load ssl, header and app.
        if not self.is_loaded:
            self.load()

        process_id = os.getpid()
        self.logger.info(colorize(f"Start MercuryServer on process [{process_id}]", fg='green'))

        # serve main flow
        await self.startup(sockets=sockets)
        if self.should_exit:
            return
        await self.main_loop()
        await self.shutdown(sockets=sockets)

        self.logger.info(f"Finished the MercuryServer on process [{process_id}]")

    async def startup(self, sockets: Optional[List] = None) -> None:
        # call lifespan startup
        await self.lifespan.startup()
        if self.lifespan.should_exit:
            self.should_exit = True
            return

        # create server serve socket
        loop = asyncio.get_running_loop()
        protocol = functools.partial(HttpProtocol, server=self)
        listeners: Sequence[socket.SocketType]

        if sockets is not None:
            listeners = []
        elif self.fd is not None:
            listeners = []
        elif self.uds is not None:
            listeners = []
        else:
            try:
                server = await loop.create_server(
                    protocol, host=self.host, port=self.port, ssl=self.ssl, backlog=2048,
                )
            except OSError as e:
                self.logger.error(e)
                await self.lifespan.shutdown()
                sys.exit(1)

            assert server.sockets is not None
            listeners = server.sockets
            self.servers = [server]

        if sockets is None:
            self.log_started_message(listeners)
        else:
            pass

        self.is_started = True

    async def on_tick(self, counter: int) -> bool:
        if counter % 10 == 0:
            self.default_headers = self.encoded_headers

        if self.should_exit:
            return True
        return False

    async def main_loop(self) -> None:
        counter = 0
        should_exit = await self.on_tick(counter)
        while not should_exit:
            counter += 1
            counter = counter % 864000
            await asyncio.sleep(0.1)
            should_exit = await self.on_tick(counter)

    async def shutdown(self, sockets: Optional[List[socket.socket]] = None) -> None:
        self.logger.info("Shutting down...")

        for server in self.servers:
            server.close()

        for sock in sockets or []:
            sock.close()

        for server in self.servers:
            await server.wait_closed()

        # Request shutdown on all existing connections
        for connection in list(self.connections):
            connection.shutdown()
        await asyncio.sleep(0.1)

        # Wait for existing connections to finish sending response
        if self.connections and not self.force_exit:
            msg = "Waiting for connections to close. (CTRL+C to force quit)"
            self.logger.info(msg)
            while self.connections and not self.force_exit:
                await asyncio.sleep(0.1)

        # Wait for existing tasks to complete
        if self.tasks and not self.force_exit:
            self.logger.info("Waiting for background tasks to complete. (CTRL+C to force quit)")
            while self.tasks and not self.force_exit:
                await asyncio.sleep(0.1)

        # Send the lifespan shutdown event and wait for application shutdown
        if not self.force_exit:
            await self.lifespan.shutdown()

    def _install_signal_handlers(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            # Signals can only be listened to from the main thread.
            return

        loop = asyncio.get_running_loop()

        try:
            for sig in HANDLED_SIGNALS:
                loop.add_signal_handler(sig, self._handle_exit, sig, None)
        except NotImplementedError:  # pragma: no cover
            # Windows
            for sig in HANDLED_SIGNALS:
                signal.signal(sig, self._handle_exit)

    def _handle_exit(self, sig: int, frame: Optional[FrameType]) -> None:
        if self.should_exit and sig == signal.SIGINT:
            self.force_exit = True
        else:
            self.should_exit = True

    def log_started_message(self, listeners: Sequence[socket.SocketType]) -> None:
        if self.fd is not None:
            pass
        elif self.uds is not None:
            pass
        else:
            host = "0.0.0.0" if self.host is None else self.host

            port = self.port
            if port == 0:
                port = listeners[0].getsockname()[1]

            protocol_name = "http"

            message = f"MercuryServer running on {protocol_name}://{host}:{port} (Press CTRL+C to quit)"
            self.logger.info(message)
