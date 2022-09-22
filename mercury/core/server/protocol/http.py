import http
import logging
import urllib.parse

from asyncio import Protocol, Transport

from mercury.type import List, Tuple, Literal, Optional, TYPE_CHECKING

from .utils import get_server_addr, get_client_addr
from .parser import HttpParserError, HttpParserUpgrade, HttpRequestParser

if TYPE_CHECKING:
    from mercury.type import HTTPScope
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

    def __init__(self, server: "Server") -> None:
        self.server = server
        self.server_handler: Optional["ServerHandler"] = None
        self.parser: HttpRequestParser = HttpRequestParser(self)
        self.transport: Optional[Transport] = None
        self.error_logger = logging.getLogger("mercury.server.error")
        self.access_logger = logging.getLogger("mercury.server.access")

        # HTTP Connection Scope
        self.url = b""
        self.scope: Optional["HTTPScope"] = None
        self.scheme: Optional[Literal["https", "http"]] = None
        self.headers: List[Tuple[bytes, bytes]] = []
        self.server_addr: Optional[Tuple[str, int]] = None
        self.client_addr: Optional[Tuple[str, int]] = None

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
        print("on_url done")

    def on_header(self, name: bytes, value: bytes) -> None:
        name = name.lower()
        if name == b"expect" and value.lower() == b"100-continue":
            pass
        self.headers.append((name, value))
        print("on_header done")

    def on_header_complete(self) -> None:
        http_version = self.parser.get_http_version()
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

        self.server_handler = self.server.handler_class(
            scope=self.scope,
            transport=self.transport,
            keep_alive=http_version != "1.0",
        )
        print("on_header_complete done")

    def on_body(self, body: bytes) -> None:
        if self.parser.should_upgrade():
            return

        self.body += body

        HIGH_WATER_LIMIT = 65536
        if len(self.body) > HIGH_WATER_LIMIT:
            pass
        print("on_body done")

    def on_message_complete(self) -> None:
        print("on_message_complete done")
