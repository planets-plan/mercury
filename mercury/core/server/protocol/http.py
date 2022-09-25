import asyncio
import http
import logging
import urllib.parse
import traceback

from collections import deque
from asyncio import Protocol, Transport

from mercury.type import List, Tuple, Literal, Optional, TYPE_CHECKING

from .utils import get_server_addr, get_client_addr
from .parser import HttpParserError, HttpParserUpgrade, HttpRequestParser

if TYPE_CHECKING:
    from mercury.type import Deque
    from mercury.type import HTTPScope, ASGI3Application
    from mercury.core.server.server import Server, ServerHandler


def _get_status_line(status_code: int) -> bytes:
    try:
        phrase = http.HTTPStatus(status_code).phrase.encode()
    except ValueError:
        phrase = b""
    return b"".join([b"HTTP/1.1 ", str(status_code).encode(), b" ", phrase, b"\r\n"])


STATUS_LINE = {
    status_code: _get_status_line(status_code) for status_code in range(100, 600)
}


class HttpProtocol(Protocol):
    """
    ASGI HTTP sub-specification's asyncio protocol, using llhttp as parser.
    """
    count = 1

    def __init__(self, server: "Server", _loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        self.server = server
        self.loop = _loop or asyncio.get_running_loop()
        self.handler: Optional["ServerHandler"] = None
        self.parser: HttpRequestParser = HttpRequestParser(self)
        self.transport: Optional[Transport] = None
        self.error_logger = logging.getLogger("mercury.server.error")
        self.access_logger = logging.getLogger("mercury.server.access")

        # State
        self.is_read_paused: bool = False
        self.is_write_paused: bool = False

        self._write_flag: asyncio.Event = asyncio.Event()
        self._write_flag.set()

        # Connection State
        self.is_keep_alive: bool = False
        self.is_100_continue: bool = False
        self.is_disconnected: bool = False

        # Request State
        self.body: bytes = b""
        self.more_body: bool = True

        # Response State
        self.excepted_content_length = 0
        self.is_chunked_encoding: Optional[bool] = None
        self.is_response_start: bool = False
        self.is_response_complete: bool = False

        # HTTP Connection Scope
        self.url = b""
        self.scope: Optional["HTTPScope"] = None
        self.scheme: Optional[Literal["https", "http"]] = None
        self.headers: List[Tuple[bytes, bytes]] = []
        self.server_addr: Optional[Tuple[str, int]] = None
        self.client_addr: Optional[Tuple[str, int]] = None
        self.pipeline: Deque[Tuple["ServerHandler", "ASGI3Application"]] = deque()
        print(f"you have {HttpProtocol.count} protocol")
        HttpProtocol.count += 1

    def connection_made(self, transport: Transport) -> None:
        # TODO logging
        # TODO connections manage | flow manage
        self.server.connections.add(self)
        self.transport = transport
        self.server_addr = get_server_addr(transport)
        self.client_addr = get_client_addr(transport)
        self.scheme = "https" if self.server.is_ssl else "http"

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.server.connections.discard(self)

    def _handle_upgrade(self):
        pass

    def _send_400_response(self, msg: str) -> None:
        content = [STATUS_LINE[400]]
        for name, value in self.server.default_headers:
            content.extend([name, b": ", value, b"\r\n"])
        content.extend(
            [
                b"content-type: text/plain; charset=utf-8\r\n",
                b"content-length: " + str(len(msg)).encode("ascii") + b"\r\n",
                b"connection: close\r\n",
                b"\r\n",
                msg.encode("ascii"),
            ]
        )
        self.transport.write(b"".join(content))
        self.transport.close()

    def data_received(self, data: bytes) -> None:
        try:
            self.parser.feed_data(data)
        except HttpParserError as e:
            msg = "Invalid HTTP request received."
            self.error_logger.warning(f"{msg} {str(e)}.")
            self._send_400_response(msg)
            return
        except HttpParserUpgrade:
            self._handle_upgrade()

    def eof_received(self) -> Optional[bool]:
        pass

    def shutdown(self) -> None:
        if self.handler is None or self.is_response_complete:
            self.transport.close()
        else:
            pass

    # llhttp callback
    def on_message_begin(self) -> None:
        self.scope = {
            "type": "http",
            "asgi": {"version": self.server.asgi_version, "spec_version": "2.3"},
            "server": self.server_addr,
            "client": self.client_addr,
            "scheme": self.scheme,
            "root_path": self.server.root_path,
            "headers": self.headers
        }

    def on_url(self, url: bytes) -> None:
        self.url += url

    def on_header(self, name: bytes, value: bytes) -> None:
        name = name.lower()
        if name == b"expect" and value.lower() == b"100-continue":
            self.is_100_continue = True
        self.headers.append((name, value))

    async def waite_until_can_write(self) -> None:
        await self._write_flag.wait()

    def pause_reading(self) -> None:
        if not self.is_read_paused:
            self.is_read_paused = True
            self.transport.pause_reading()

    def resume_reading(self) -> None:
        if self.is_read_paused:
            self.is_read_paused = False
            self.transport.resume_reading()

    def _pause_writing(self) -> None:
        if not self.is_write_paused:
            self.is_write_paused = True
            self._write_flag.clear()

    def _resume_writing(self) -> None:
        if self.is_write_paused:
            self.is_write_paused = False
            self._write_flag.set()

    def on_headers_complete(self) -> None:
        http_version = self.parser.get_http_version()
        self.is_keep_alive = self.parser.should_keep_alive()
        self.scope["http_version"] = http_version if http_version else "1.1"

        method = self.parser.get_method()
        self.scope["method"] = method.decode("ascii")

        if self.parser.should_upgrade():
            return

        parsed_url = urllib.parse.urlparse(self.url)
        raw_path = parsed_url.path
        path = raw_path.decode("ascii")
        if "%" in path:
            path = urllib.parse.unquote(path)
        self.scope["path"] = path
        self.scope["raw_path"] = raw_path
        self.scope["query_string"] = parsed_url.query or b""

        # TODO handle 503

        current_handler = self.handler
        self.handler = self.server.handler_class(scope=self.scope, protocol=self, transport=self.transport)
        if current_handler is None or self.is_response_complete:
            task = self.loop.create_task(self.handler.run(self.server.loaded_app))
            task.add_done_callback(self.server.tasks.discard)
            self.server.tasks.add(task)
        else:
            self.pause_reading()
            self.pipeline.appendleft((self.handler, self.server.loaded_app))

    def on_body(self, body: bytes) -> None:
        if self.parser.should_upgrade() or self.is_response_complete:
            return

        self.body += body
        if len(self.body) > 65536:
            self.pause_reading()
        self.handler.message_event.set()

    def on_message_complete(self) -> None:
        if self.parser.should_upgrade() or self.is_response_complete:
            return
        self.more_body = False
        if self.handler:
            self.handler.message_event.set()
