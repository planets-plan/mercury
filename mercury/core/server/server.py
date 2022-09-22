import os
import sys
import ssl
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
    from mercury.type import ASGIApplication, ServerConfigOptions


logger = logging.getLogger("mercury.server")

HANDLED_SIGNALS = (
    signal.SIGINT,  # Unix signal 2. Sent by Ctrl+C.
    signal.SIGTERM,  # Unix signal 15. Sent by `kill <pid>`.
)


def create_ssl_context(
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


class Server:

    @property
    def asgi_version(self) -> Literal["2.0", "3.0"]:
        return self._asgi_version

    def __init__(self,  **options: "ServerConfigOptions") -> None:
        # base options
        self.app: Optional[Union["ASGIApplication", "Callable", str]] = options.get("app")
        self.host = options.get("host", None)
        self.port = options.get("port", None)
        self.uds = options.get("uds", None)
        self.fd = options.get("fd", None)
        self.debug = options.get("debug", False)
        self.root_path: str = options.get("root_path", "")
        self.worker_number = options.get("worker_number", 1)
        self.specification = options.get("specification", "auto")

        # reload
        self.reload = options.get("reload", False)
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

        # header options
        self.headers: Optional[Tuple[str, str]] = options.get("headers", None)
        self.encoded_headers: List[Tuple[bytes, bytes]] = []
        self.date_header: bool = options.get("date_header", False)
        self.proxy_header: bool = options.get("proxy_header", False)
        self.server_header: bool = options.get("server_header", False)

        # attribute
        self.lifespan: Optional["Lifespan"] = None
        self.loaded_app: Optional[Callable] = None
        self.handler_class: Type[ServerHandler] = ServerHandler

        # state
        self.total_requests = 0
        self.connections: Set[asyncio.Protocol] = set()
        self.tasks: Set[asyncio.Task] = set()
        self.default_headers: List[Tuple[bytes, bytes]] = []
        self._asgi_version: Optional[Literal["2.0", "3.0"]] = None

        self.is_started: bool = False
        self.force_exit: bool = False
        self.should_exit: bool = False
        self.is_ssl: bool = bool(self.ssl_keyfile or self.ssl_certfile)
        self.is_loaded: bool = False
        self.is_windows: bool = platform.system().lower() == "windows"
        self.is_subprocess: bool = bool(self.reload or self.worker_number > 1)

        # start load func, load ssl, header and app.
        self.load()

    def load(self) -> None:
        # load ssl
        if self.is_ssl:
            assert self.ssl_certfile
            self.ssl = create_ssl_context(
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
        if b"server" not in dict(self.encoded_headers) and self.server_header:
            self.encoded_headers.insert(0, (b"server", b"server"))

        # load app
        try:
            self.loaded_app = import_app_from_string(self.app)
        except ImportFromStringError as e:
            logger.error(f"Error loading ASGI app. {e}")
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

        if self.debug:
            self.loaded_app = DebugMiddleware(self.loaded_app)

        self.is_loaded = True

    def run(self, sockets: Optional[List[socket.socket]] = None) -> None:
        return asyncio.run(self.server(sockets=sockets))

    async def server(self, sockets: Optional[List[socket.socket]] = None) -> None:
        process_id = os.getpid()

        if self.specification != "wsgi":
            self.lifespan = LifespanOff()
        else:
            self.lifespan = LifespanOn(self)

        self.install_signal_handlers()

        logger.info(colorize(f"Start server process [{process_id}]", fg='green'))

        await self.startup(sockets=sockets)
        if self.should_exit:
            return
        await self.main_loop()
        await self.shutdown(sockets=sockets)

        logger.info(f"Finished server process [{process_id}]")

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

    def _log_started_message(self, listeners: Sequence[socket.SocketType]) -> None:

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
            logger.info(message)

    async def startup(self, sockets: Optional[List] = None) -> None:
        await self.lifespan.startup()
        if self.lifespan.should_exit:
            self.should_exit = True
            return

        loop = asyncio.get_running_loop()
        protocol = functools.partial(HttpProtocol, server=self)
        listeners: Sequence[socket.SocketType]

        if sockets is not None:
            pass
        elif self.fd is not None:
            pass
        elif self.uds is not None:
            pass
        else:
            try:
                server = await loop.create_server(
                    protocol,
                    host=self.host,
                    port=self.port,
                    ssl=None,
                    backlog=2048,
                )
            except OSError as e:
                logger.error(e)
                await self.lifespan.shutdown()
                sys.exit(1)

            assert server.sockets is not None
            listeners = server.sockets
            self.servers = [server]

        if sockets is None:
            self._log_started_message(listeners)
        else:
            pass

        self.is_started = True

    async def shutdown(self, sockets: Optional[List] = None) -> None:
        logger.info("Shutting down...")

        for server in self.servers:
            server.close()
        for sock in sockets or []:
            sock.close()
        for server in self.servers:
            await server.wait_closed()

        for connection in list(self.connections):
            connection.shutdown()
        await asyncio.sleep(0.1)

    def install_signal_handlers(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            # Signals can only be listened to from the main thread.
            return

        loop = asyncio.get_event_loop()

        try:
            for sig in HANDLED_SIGNALS:
                loop.add_signal_handler(sig, self.handle_exit, sig, None)
        except NotImplementedError:  # pragma: no cover
            # Windows
            for sig in HANDLED_SIGNALS:
                signal.signal(sig, self.handle_exit)

    def handle_exit(self, sig: int, frame: Optional[FrameType]) -> None:

        if self.should_exit and sig == signal.SIGINT:
            self.force_exit = True
        else:
            self.should_exit = True


class ServerHandler:

    def __init__(self):
        pass
