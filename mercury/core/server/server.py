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
    from mercury.type import (
        Scope,
        ASGISendEvent,
        ASGIApplication,
        ASGIReceiveEvent,
        ASGI3Application,
        ServerConfigOptions,
        HTTPResponseStartEvent,
    )


logger = logging.getLogger("mercury.server")

HANDLED_SIGNALS = (
    signal.SIGINT,  # Unix signal 2. Sent by Ctrl+C.
    signal.SIGTERM,  # Unix signal 15. Sent by `kill <pid>`.
)
HTTP_HEADER_NAME_CHECK_RE = re.compile(b'[\x00-\x1F\x7F()<>@,;:[]={} \t\\"]')
HTTP_HEADER_VALUE_CHECK_RE = re.compile(b"[\x00-\x1F\x7F]")


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
        self.lifespan: Optional["Lifespan"] = None
        self.loaded_app: Optional[Callable] = None
        self.handler_class: Type[ServerHandler] = ServerHandler

        # server state
        self.tasks: Set[asyncio.Task] = set()
        self.connections: Set[asyncio.Protocol] = set()
        self.request_number: int = 0
        self._asgi_version: Optional[Literal["2.0", "3.0"]] = None

        # judge attribute
        self.is_exited: bool = False
        self.is_started: bool = False
        self.should_exit: bool = False
        self.is_ssl: bool = bool(self.ssl_keyfile or self.ssl_certfile)
        self.is_loaded: bool = False
        self.is_windows: bool = platform.system().lower() == "windows"
        self.need_subprocess: bool = bool(self.reload or self.worker_number > 1)

        # start load func, load ssl, header and app.
        self.load()

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

    def _handle_exit(self, sig: int, frame: Optional[FrameType]) -> None:
        if self.should_exit and sig == signal.SIGINT:
            self.force_exit = True
        else:
            self.should_exit = True

    def _install_signal_handlers(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            # Signals can only be listened to from the main thread.
            return

        loop = asyncio.get_event_loop()

        try:
            for sig in HANDLED_SIGNALS:
                loop.add_signal_handler(sig, self._handle_exit, sig, None)
        except NotImplementedError:  # pragma: no cover
            # Windows
            for sig in HANDLED_SIGNALS:
                signal.signal(sig, self._handle_exit)

    async def server(self, sockets: Optional[List[socket.socket]] = None) -> None:
        process_id = os.getpid()

        if self.specification != "wsgi":
            self.lifespan = LifespanOff()
        else:
            self.lifespan = LifespanOn(self)

        # bind func to handle the signal
        self._install_signal_handlers()

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


class ServerHandler:

    def __init__(self, scope: "Scope", protocol: "HttpProtocol", transport: asyncio.Transport) -> None:
        self.scope = scope
        self.protocol = protocol
        self.transport = transport

        self.status_line = {
            status_code: self._get_status_line(status_code) for status_code in range(100, 600)
        }

        # response stare
        self.is_started = False
        self.is_finished = False
        self.is_chunked_encoding = None

    def _get_status_line(status_code: int) -> bytes:
        try:
            phrase = http.HTTPStatus(status_code).phrase.encode()
        except ValueError:
            phrase = b""
        return b"".join([b"HTTP/1.1 ", str(status_code).encode(), b" ", phrase, b"\r\n"])

    def _send_response_start(self, message: "ASGISendEvent") -> None:
        message_type = message.get("type", "")
        if message_type != "http.response.start":
            raise RuntimeError(
                f"Expected ASGI message 'http.response.start', bug got {message_type}."
            )
        message = cast("HTTPResponseStartEvent", message)

        self.is_started = True
        self.protocol.is_100_continue = False

        status_code: int = message.get("status")
        headers: List[Tuple[bytes, bytes]] = self.protocol.server.default_headers + list(message.get("headers", []))

        close_header = (b"connection", b"close")
        if close_header in self.scope["headers"] and close_header not in headers:
            headers = headers + [close_header]

        content: List[bytes] = [self.status_line.get(status_code)]

        for name, value in headers:
            if HTTP_HEADER_NAME_CHECK_RE.search(name):
                raise RuntimeError("Invalid HTTP header name.")
            if HTTP_HEADER_VALUE_CHECK_RE.search(value):
                raise RuntimeError("Invalid HTTP header value.")

            name = name.lower()
            if name == b"content-length" and self.chunked_encoding is None:
                self.excepted_content_length = int(value.decode())
            elif name == b"transfer-encoding" and value.lower() == b"chunked":
                self.excepted_content_length = 0
                self.chunked_encoding = True
            elif name == b"connection" and value.lower() == b"close":
                self.keepalive = False
            content.extend([name, b": ", value, b"\r\n"])

        if self.chunked_encoding is None and self.scope["method"] != "HEAD" and status_code not in (204, 304):
            self.chunked_encoding = True
            content.append(b"transfer-encoding: chunked\r\n")

        content.append(b"\r\n")
        self.transport.write(b"".join(content))

    def _send_response_body(self, message: "ASGISendEvent"):
        message_type = message.get("type", "")
        if message_type != "http.response.body":
            raise RuntimeError(
                f"Expected ASGI message 'http.response.body', but got '{message_type}'."
            )

        body: bytes = cast(bytes, message.get("body" b""))
        more_body: bool = message.get("more_body", False)

        # handle chunk
        if self.scope["method"] == "HEAD":
            self.excepted_content_length = 0
        elif self.chunked_encoding:
            if body:
                content = [b"%x\r\n" % len(body), body, b"\r\n"]
            else:
                content = []
            if not more_body:
                content.append(b"0\r\n\r\n")
            self.transport.write(b"".join(content))
        else:
            content_length = len(body)
            if content_length > self.excepted_content_length:
                raise RuntimeError("Response content longer than Content-Length")
            else:
                self.excepted_content_length -= content_length
            self.transport.write(body)

        if not more_body:
            if self.excepted_content_length != 0:
                raise RuntimeError("Response content shorter than Content-Length")
            self.is_finished = True
            self.message_event.set()
            if not self.keepalive:
                self.transport.close()
            self.on_response()


    async def send(self, message: "ASGISendEvent") -> None:
        if self.protocol.is_write_paused and not self.protocol.is_disconnected:
            await self.protocol.drain()

        if self.protocol.is_disconnected:
            return

        if not self.is_started:
            self._send_response_start(message)

        elif not self.is_finished:
            self._send_response_body(message)
        else:
            # response is already sent
            raise RuntimeError(
                f"Unexpected ASGI message '{message['type']}' sent, after response already completed."
            )

    def handle_100_continue(self) -> None:
        self.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        self.protocol.is_100_continue = False

    async def receive(self) -> "ASGIReceiveEvent":
        if self.protocol.is_100_continue and not self.transport.is_closing():
            self.handle_100_continue()

        if not self.disconnected and not self.is_finished:
            pass

        message: dict

        if self.disconnected or self.is_finished:
            message = {"type": "http.disconnect"}
        else:
            message = {
                "type": "http.request",
                "body": self.body,
                "more_body": self.more_body,
            }
            self.body = b""

        return message

    async def run(self, application: "ASGI3Application") -> None:
        try:
            result = await application(self.scope, self.receive, self.send)
        except BaseException as e:
            msg = "Exception in ASGI application\n"
            self.logger.errorr(msg, exc_info=e)

            if not self.is_started:
                await self._send_500_response()
            else:
                self.transport.close()
        else:
            if result is not None:
                msg = ""
                self.transport.close()
            elif not self.is_started and not self.is_disconnected:
                msg = ""
                await self.send_500_response()
            elif not self.is_finished and not self.is_disconnected:
                msg = ""
                self.transport.close()
