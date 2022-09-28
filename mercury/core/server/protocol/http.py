import re
import http
import logging
import asyncio
import urllib.parse

from collections import deque
from asyncio import Protocol, Transport

from mercury.type import cast, List, Tuple, Union, Literal, Optional, Callable, TYPE_CHECKING

from .utils import get_server_addr, get_client_addr
from .parser import HttpParserError, HttpParserUpgrade, HttpRequestParser

if TYPE_CHECKING:
    from mercury.type import Deque
    from mercury.type import (
        Scope,
        HTTPScope,
        ASGISendEvent,
        ASGIReceiveEvent,
        ASGI3Application,
        HTTPRequestEvent,
        HTTPDisconnectEvent,
        HTTPResponseBodyEvent,
        HTTPResponseStartEvent,
    )
    from mercury.core.server.server import Server, ServerHandler


def _get_status_line(status_code: int) -> bytes:
    try:
        phrase = http.HTTPStatus(status_code).phrase.encode()
    except ValueError:
        phrase = b""
    return b"".join([b"HTTP/1.1 ", str(status_code).encode(), b" ", phrase, b"\r\n"])


STATUS_LINE = {status_code: _get_status_line(status_code) for status_code in range(100, 600)}
HTTP_HEADER_NAME_CHECK_RE = re.compile(b'[\x00-\x1F\x7F()<>@,;:[]={} \t\\"]')
HTTP_HEADER_VALUE_CHECK_RE = re.compile(b"[\x00-\x1F\x7F]")


class ASGIHttpHandler:
    def __init__(self, scope: "Scope", protocol: "HttpProtocol", transport: "asyncio.Transport", on_response: Callable[..., None]) -> None:
        self.server = protocol.server
        self.logger = protocol.server.logger
        self.transport = transport
        self.on_response = on_response
        self.event_flag = asyncio.Event()

        # Connection State
        self.scope = scope
        self.protocol = protocol
        self.is_disconnected: bool = False

        # Request State
        self.body: bytes = b""
        self.more_body: bool = True

        # Response State
        self.excepted_content_length = 0
        self.is_response_start: bool = False
        self.is_chunked_encoding: Optional[bool] = None
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

        self.is_response_start = True
        self.protocol.is_100_continue = False

        status_code: int = message.get("status")
        headers: List[Tuple[bytes, bytes]] = self.protocol.server.default_headers + list(message.get("headers", []))

        close_header = (b"connection", b"close")
        if close_header in self.scope["headers"] and close_header not in headers:
            headers = headers + [close_header]

        content: List[bytes] = [STATUS_LINE.get(status_code)]

        for name, value in headers:
            if HTTP_HEADER_NAME_CHECK_RE.search(name):
                raise RuntimeError("Invalid HTTP header name.")
            if HTTP_HEADER_VALUE_CHECK_RE.search(value):
                raise RuntimeError("Invalid HTTP header value.")

            name = name.lower()
            if name == b"content-length" and self.is_chunked_encoding is None:
                self.excepted_content_length = int(value.decode())
                self.is_chunked_encoding = False
            elif name == b"transfer-encoding" and value.lower() == b"chunked":
                self.excepted_content_length = 0
                self.is_chunked_encoding = True
            elif name == b"connection" and value.lower() == b"close":
                self.keepalive = False
            content.extend([name, b": ", value, b"\r\n"])

        if self.is_chunked_encoding is None and self.scope["method"] != "HEAD" and status_code not in (204, 304):
            self.is_chunked_encoding = True
            content.append(b"transfer-encoding: chunked\r\n")

        content.append(b"\r\n")
        self.transport.write(b"".join(content))

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
            self.excepted_content_length = 0
        elif self.is_chunked_encoding:
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
            self.is_response_complete = True
            self.event_flag.set()
            if not self.protocol.is_keepalive:
                self.transport.close()
            self.on_response()

    def handle_100_continue(self) -> None:
        self.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        self.protocol.is_100_continue = False

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

            if not self.is_response_start:
                await self.send_500_response()
            else:
                self.transport.close()
        else:
            if result is not None:
                self.logger.error(f"ASGI callable should return None, but returned '{result}'.")
                self.transport.close()
            elif not self.is_response_start and not self.is_disconnected:
                self.logger.error("ASGI callable returned without starting response.")
                await self.send_500_response()
            elif not self.is_response_complete and not self.is_disconnected:
                self.logger.error("ASGI callable returned without completing response.")
                self.transport.close()

    async def send(self, message: "ASGISendEvent") -> None:
        """ Call all ASGISendEvent(write) event by connection state """
        if self.protocol.is_write_paused and not self.is_disconnected:
            # 如果 protocol 没有在处理写事件并且次处理器未被断开：等待直到可以执行写事件
            await self.protocol.waite_until_can_write()

        if self.is_disconnected:
            # 如果处理器处于断开状态
            return

        if not self.is_response_start:
            # response not start
            self._send_response_start(message)

        elif not self.is_response_complete:
            # response not complete
            self._send_response_body(message)

        else:
            # response is already sent
            raise RuntimeError(
                f"Unexpected ASGI message '{message['type']}' sent, after response already completed."
            )

    async def receive(self) -> "ASGIReceiveEvent":
        if self.protocol.is_100_continue and not self.transport.is_closing():
            self.handle_100_continue()

        if not self.is_disconnected and not self.is_response_complete:
            self.protocol.pause_read()
            await self.event_flag.wait()
            self.event_flag.clear()

        message: "Union[HTTPDisconnectEvent, HTTPRequestEvent]"
        if self.is_disconnected or self.is_response_complete:
            message = {"type": "http.disconnect"}
        else:
            message = {
                "type": "http.request",
                "body": self.protocol.body,
                "more_body": self.protocol.body,
            }
            self.protocol.body = b""

        return message


class HttpProtocol(Protocol):
    """
    ASGI HTTP sub-specification's asyncio protocol, using llhttp as parser.
    """
    def __init__(self, server: "Server", _loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        self.loop = _loop or asyncio.get_running_loop()
        self.server = server
        self.parser: HttpRequestParser = HttpRequestParser(self)
        self.handler: Optional["ASGIHttpHandler"] = None
        self.transport: Optional[Transport] = None
        self.error_logger = logging.getLogger("mercury.server.error")
        self.access_logger = logging.getLogger("mercury.server.access")

        # State
        self._write_flag: asyncio.Event = asyncio.Event()
        self._write_flag.set()

        self.is_read_paused: bool = False
        self.is_write_paused: bool = False
        self.timeout_keepalive: int = 5
        self.timeout_keepalive_task: Optional[asyncio.TimerHandle] = None

        # HTTP Connection Scope
        self.is_keepalive: bool = False
        self.is_100_continue: bool = False

        self.url = b""
        self.scope: Optional["HTTPScope"] = None
        self.scheme: Optional[Literal["https", "http"]] = None
        self.headers: List[Tuple[bytes, bytes]] = []
        self.server_addr: Optional[Tuple[str, int]] = None
        self.client_addr: Optional[Tuple[str, int]] = None
        self.pipeline: Deque[Tuple["ServerHandler", "ASGI3Application"]] = deque()

    # http connection flow control function
    def pause_read(self) -> None:
        if not self.is_read_paused:
            self.is_read_paused = True
            self.transport.pause_reading()

    def resume_read(self) -> None:
        if self.is_read_paused:
            self.is_read_paused = False
            self.transport.resume_reading()

    def pause_write(self) -> None:
        if not self.is_write_paused:
            self.is_write_paused = True
            self._write_flag.clear()

    def resume_write(self) -> None:
        if self.is_write_paused:
            self.is_write_paused = False
            self._write_flag.set()

    # asyncio protocol abstract function
    def connection_made(self, transport: Transport) -> None:
        """ Called when a connection is made. """
        self.server.connections.add(self)

        self.transport = transport
        self.server_addr = get_server_addr(transport)
        self.client_addr = get_client_addr(transport)
        self.scheme = "https" if bool(self.transport.get_extra_info("sslcontext")) else "http"

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """ Called when the connection is lost or closed. """
        self.server.connections.discard(self)

        if self.handler and not self.handler.is_response_complete:
            self.handler.is_disconnected = True

        if self.handler is not None:
            self.handler.event_flag.set()

        if self.transport is not None:
            self.resume_write()

        if exc is None:
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

    # llhttp callback need
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

    def _unset_keepalive_if_required(self) -> None:
        if self.timeout_keepalive_task is not None:
            self.timeout_keepalive_task.cancel()
            self.timeout_keepalive_task = None

    async def waite_until_can_write(self) -> None:
        await self._write_flag.wait()

    def _timeout_keepalive_handler(self) -> None:
        if not self.transport.is_closing():
            self.transport.close()

    def _handler_callback(self) -> None:
        self.server.request_number += 1

        if self.transport.is_closing():
            return

        self._unset_keepalive_if_required()

        self.timeout_keepalive_task = self.loop.call_later(self.timeout_keepalive, self._timeout_keepalive_handler)

        self.resume_read()

        if self.pipeline:
            handler, application = self.pipeline.pop()
            task = self.loop.create_task(handler.run(application))
            task.add_done_callback(self.server.tasks.discard)
            self.server.tasks.add(task)

    # llhttp callback
    def on_message_begin(self) -> None:
        self.url = b""
        self.headers = []
        self.is_100_continue = False
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

    def on_headers_complete(self) -> None:
        """ Invoked when headers are completed

        When headers are completed, we can:
        1. get the connection states such as http_version, is_keepalive...
        2. fill asgi http connection scope dict
        3. create ASGIHttpHandler instance to handle http request or response event
        """
        if self.parser.should_upgrade():
            return

        # get connection state
        http_version = self.parser.get_http_version()
        self.is_keepalive = self.parser.should_keep_alive()
        method = self.parser.get_method()
        parsed_url = urllib.parse.urlparse(self.url)
        raw_path = parsed_url.path
        path = raw_path.decode("ascii")
        if "%" in path:
            path = urllib.parse.unquote(path)

        # fill asgi http connection scope
        self.scope["path"] = path
        self.scope["method"] = method.decode("ascii")
        self.scope["raw_path"] = raw_path
        self.scope["query_string"] = parsed_url.query or b""
        self.scope["http_version"] = http_version if http_version else "1.1"

        # TODO handle 503

        # record old handler and create new ASGIHttpHandler
        old_handler = self.handler
        self.handler = ASGIHttpHandler(scope=self.scope, protocol=self, transport=self.transport, on_response=self._handler_callback)

        # if not old_handler or old_handler is complete, create new task right now
        # else pause http request stream read and add this task to connection pipeline
        if old_handler is None or old_handler.is_response_complete:
            task = self.loop.create_task(self.handler.run(self.server.loaded_app))
            task.add_done_callback(self.server.tasks.discard)
            self.server.tasks.add(task)
        else:
            self.pause_read()
            self.pipeline.appendleft((self.handler, self.server.loaded_app))

    def on_body(self, body: bytes) -> None:
        """ Invoked when body  """
        if self.parser.should_upgrade() or self.handler.is_response_complete:
            return

        self.handler.body += body
        if len(self.handler.body) > 65536:
            self.pause_read()
        # when request body is parser complete
        self.handler.event_flag.set()

    def on_message_complete(self) -> None:
        if self.parser.should_upgrade() or self.handler.is_response_complete:
            return
        self.handler.more_body = False
        if self.handler:
            self.handler.event_flag.set()

    # connection control function
    def shutdown(self) -> None:
        if self.handler is None or self.handler.is_response_complete:
            self.transport.close()
        else:
            self.handler.is_keepalive = False
