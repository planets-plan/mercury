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
    from mercury.type import Scope, HTTPScope, ASGI3Application
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


class HttpRequest:
    pass


class HttpResponse:
    pass


class ASGIHttpHandler:
    def __init__(self, scope: "Scope", server: "Server", protocol: "HttpProtocol") -> None:
        self.logger = server.logger
        self.message_event = asyncio.Event()
        self.status_line = {status_code: self._get_status_line(status_code) for status_code in range(100, 600)}

        # Request State
        self.body: bytes = b""
        self.more_body: bool = True

        # Response State
        self.excepted_content_length = 0
        self.is_chunked_encoding: Optional[bool] = None
        self.is_response_start: bool = False
        self.is_response_complete: bool = False

    @staticmethod
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

        self.protocol.is_response_start = True
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
            if name == b"content-length" and self.protocol.is_chunked_encoding is None:
                self.protocol.excepted_content_length = int(value.decode())
                self.protocol.is_chunked_encoding = False
            elif name == b"transfer-encoding" and value.lower() == b"chunked":
                self.protocol.excepted_content_length = 0
                self.protocol.is_chunked_encoding = True
            elif name == b"connection" and value.lower() == b"close":
                self.keepalive = False
            content.extend([name, b": ", value, b"\r\n"])

        if self.protocol.is_chunked_encoding is None and self.scope["method"] != "HEAD" and status_code not in (204, 304):
            self.protocol.is_chunked_encoding = True
            content.append(b"transfer-encoding: chunked\r\n")

        content.append(b"\r\n")
        self.transport.write(b"".join(content))

    def _on_response_complete(self) -> None:
        self.protocol.server.request_number += 1

        if self.transport.is_closing():
            return

        # self._unset_keepalive_if_requite()
        #
        # self.timeout_keep_alive_task = self.protocol.loop.call_later(
        #     self.timeout_keep_alive, self.timemout_keep_alive_handler
        # )

        self.protocol.resume_reading()

        if self.protocol.pipeline:
            handler, application = self.protocol.pipeline.pop()
            task = self.protocol.loop.create_task(self.run(application))
            task.add_done_callback(self.protocol.server.tasks.discard)
            self.protocol.server.tasks.add(task)

    def _send_response_body(self, message: "ASGISendEvent"):
        message_type = message.get("type", "")
        if message_type != "http.response.body":
            raise RuntimeError(
                f"Expected ASGI message 'http.response.body', but got '{message_type}'."
            )

        body: bytes = cast(bytes, message.get("body", b""))
        more_body: bool = message.get("more_body", False)

        # handle chunk
        if self.scope["method"] == "HEAD":
            self.protocol.excepted_content_length = 0
        elif self.protocol.is_chunked_encoding:
            if body:
                content = [b"%x\r\n" % len(body), body, b"\r\n"]
            else:
                content = []
            if not more_body:
                content.append(b"0\r\n\r\n")
            self.transport.write(b"".join(content))
        else:
            content_length = len(body)
            if content_length > self.protocol.excepted_content_length:
                raise RuntimeError("Response content longer than Content-Length")
            else:
                self.protocol.excepted_content_length -= content_length
            self.transport.write(body)

        if not more_body:
            if self.protocol.excepted_content_length != 0:
                raise RuntimeError("Response content shorter than Content-Length")
            self.protocol.is_response_complete = True
            self.message_event.set()
            if not self.protocol.is_keep_alive:
                self.transport.close()
            self._on_response_complete()

    async def send(self, message: "ASGISendEvent") -> None:
        print(f"protocol id {id(self.protocol)}")
        # not disconnected and write paused
        if self.protocol.is_write_paused and not self.protocol.is_disconnected:
            await self.protocol.waite_until_can_write()

        # disconnected
        if self.protocol.is_disconnected:
            return

        if not self.protocol.is_response_start:
            # response not start
            self._send_response_start(message)
        elif not self.protocol.is_response_complete:
            # response not complete
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

        if not self.protocol.is_disconnected and not self.protocol.is_response_complete:
            self.protocol.pause_reading()
            await self.message_event.wait()
            self.message_event.clear()

        message: "Union[HTTPDisconnectEvent, HTTPRequestEvent]"
        if self.protocol.is_disconnected or self.protocol.is_response_complete:
            message = {"type": "http.disconnect"}
        else:
            message = {
                "type": "http.request",
                "body": self.protocol.body,
                "more_body": self.protocol.body,
            }
            self.protocol.body = b""

        return message

    async def send_500_response(self) -> None:
        response_start_event: "HTTPResponseStartEvent" = {
            "type": "http.response.start",
            "status": 500,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"connection", b"close"),
            ],
        }
        await self.send(response_start_event)
        response_body_event: "HTTPResponseBodyEvent" = {
            "type": "http.response.body",
            "body": b"Internal Server Error",
            "more_body": False,
        }
        await self.send(response_body_event)

    async def run(self, application: "ASGI3Application") -> None:
        try:
            result = await application(self.scope, self.receive, self.send)
        except BaseException as e:
            msg = "Exception in ASGI application\n"
            self.logger.error(msg, exc_info=e)

            if not self.protocol.is_response_start:
                await self.send_500_response()
            else:
                self.transport.close()
        else:
            if result is not None:
                self.logger.error(f"ASGI callable should return None, but returned '{result}'.")
                self.transport.close()
            elif not self.protocol.is_response_start and not self.protocol.is_disconnected:
                self.logger.error("ASGI callable returned without starting response.")
                await self.send_500_response()
            elif not self.protocol.is_response_complete and not self.protocol.is_disconnected:
                self.logger.error("ASGI callable returned without completing response.")
                self.transport.close()


class HttpProtocol(Protocol):
    """
    ASGI HTTP sub-specification's asyncio protocol, using llhttp as parser.
    """

    def __init__(self, server: "Server", _loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        self.loop = _loop or asyncio.get_running_loop()
        self.transport: Optional[Transport] = None

        self.server = server
        self.handler: Optional["ASGIHttpHandler"] = None
        self.parser: HttpRequestParser = HttpRequestParser(self)

        self.logger = None
        self.error_logger = logging.getLogger("mercury.server.error")
        self.access_logger = logging.getLogger("mercury.server.access")

        # State
        self.is_read_paused: bool = False
        self.is_write_paused: bool = False

        self._write_flag: asyncio.Event = asyncio.Event()
        self._write_flag.set()

        # HTTP Connection Scope
        self.is_keep_alive: bool = False
        self.is_100_continue: bool = False
        self.is_disconnected: bool = False

        self.url = b""
        self.scope: Optional["HTTPScope"] = None
        self.scheme: Optional[Literal["https", "http"]] = None
        self.headers: List[Tuple[bytes, bytes]] = []
        self.server_addr: Optional[Tuple[str, int]] = None
        self.client_addr: Optional[Tuple[str, int]] = None
        self.pipeline: Deque[Tuple["ServerHandler", "ASGI3Application"]] = deque()

    def connection_made(self, transport: Transport) -> None:
        # TODO logging
        # TODO connections manage | flow manage
        # one connection_made one connection one protocol one transport
        # one connection many http
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
