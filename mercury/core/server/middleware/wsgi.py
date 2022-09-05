import asyncio
import concurrent.futures
import io
import sys

from collections import deque

from mercury.type import Deque, Tuple, Optional, Iterable
from mercury.type import (
    Environ,
    ExcInfo,
    HTTPScope,
    HTTPRequestEvent,
    HTTPResponseStartEvent,
    HTTPResponseBodyEvent,
    WSGIApplication,
    StartResponse,
    ASGISendEvent,
    ASGISendCallable,
    ASGIReceiveEvent,
    ASGIReceiveCallable,
)


def build_environ(scope: HTTPScope, message: ASGIReceiveEvent, body: io.BytesIO) -> Environ:
    """"""
    environ = {
        "REQUEST_METHOD": scope["method"],
        "SCRIPT_NAME": "",
        "PATH_INFO": scope["path"].encode("utf8").decode("latin1"),
        "QUERY_STRING": scope["query_string"].decode("ascii"),
        "SERVER_PROTOCOL": f"HTTP/{scope['http_version']}",
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": scope.get("scheme", "http"),
        "wsgi.input": body,
        "wsgi.errors": sys.stdout,
        "wsgi.multithread": True,
        "wsgi.multiprocess": True,
        "wsgi.run_once": False,
    }

    server = scope.get("server")
    if server is None:
        server = ("localhost", 80)
    environ["SERVER_NAME"] = server[0]
    environ["SERVER_PORT"] = server[1]

    client = scope.get("client")
    if client is not None:
        environ["REMOTE_ADDR"] = client[0]

    for name, value in scope.get("headers", []):
        name_str: str = name.decode("latin1")
        if name_str == "content-length":
            corrected_name = "CONTENT_LENGTH"
        elif name_str == "content-type":
            corrected_name = "CONTENT_TYPE"
        else:
            corrected_name = f"HTTP_{name_str.upper().replace('-', '_')}"

        value_str: str = value.decode("latin1")
        if corrected_name in environ:
            corrected_name_environ = environ[corrected_name]
            assert isinstance(corrected_name_environ, str)
            value_str = f"{corrected_name_environ},{value_str}"
        environ[corrected_name] = value_str

    return environ


class WSGIResponder:
    """"""

    def __init__(
        self,
        app: WSGIApplication,
        executor: concurrent.futures.ThreadPoolExecutor,
        scope: HTTPScope
    ):
        self.app = app
        self.executor = executor
        self.scope = scope
        self.status = None
        self.response_headers = None
        self.send_event = asyncio.Event()
        self.send_queue: Deque[Optional[ASGISendEvent]] = deque()
        self.loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
        self.response_started = False
        self.exc_info: Optional[ExcInfo] = None

    async def __call__(self, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        message: HTTPRequestEvent = await receive()
        body = io.BytesIO(message.get("body", b""))
        more_body = message.get("more_body", False)
        if more_body:
            body.seek(0, io.SEEK_END)
            while more_body:
                body_message: HTTPRequestEvent = (await receive())
                body.write(body_message.get("body", b""))
                more_body = body_message.get("more_body", False)
            body.seek(0)
        environ = build_environ(self.scope, message, body)
        self.loop = asyncio.get_running_loop()
        wsgi = self.loop.run_in_executor(self.executor, self.wsgi, environ, self.start_response)
        sender = self.loop.create_task(self.sender(send))

        try:
            await asyncio.wait_for(wsgi, None)
        finally:
            self.send_queue.append(None)
            self.send_event.set()
            await asyncio.wait_for(sender, None)

        if self.exc_info is not None:
            raise self.exc_info[0].with_traceback(self.exc_info[1], self.exc_info[2])

    async def sender(self, send: ASGISendCallable) -> None:
        while True:
            if self.send_queue:
                message = self.send_queue.popleft()
                if message is None:
                    return
                await send(message)
            else:
                await self.send_event.wait()
                self.send_event.clear()

    def start_response(
        self,
        status: str,
        response_headers: Iterable[Tuple[str, str]],
        exc_info: Optional[ExcInfo] = None
    ) -> None:
        self.exc_info = exc_info
        if not self.response_started:
            self.response_started = True
            status_code_str, _ = status.split(" ", 1)
            status_code = int(status_code_str)
            headers = [
                (name.encode("ascii"), value.encode("ascii"))
                for name, value in response_headers
            ]
            http_response_start_event: HTTPResponseStartEvent = {
                "type": "http.response.start",
                "status": status_code,
                "headers": headers
            }
            self.send_queue.append(http_response_start_event)
            self.loop.call_soon_threadsafe(self.send_event.set)

    def wsgi(self, environ: Environ, start_response: StartResponse) -> None:
        for chunk in self.app(environ, start_response):
            response_body: HTTPResponseBodyEvent = {
                "type": "http.response.body",
                "body": chunk,
                "more_body": True,
            }
            self.send_queue.append(response_body)
            self.loop.call_soon_threadsafe(self.send_event.set)

        empty_body: HTTPResponseBodyEvent = {
            "type": "http.response.body",
            "body": b"",
            "more_body": False,
        }
        self.send_queue.append(empty_body)
        self.loop.call_soon_threadsafe(self.send_event.set)


class WSGIMiddleware:
    """"""

    def __init__(self, app: WSGIApplication, workers: int = 10) -> None:
        self.app = app
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)

    async def __call__(
        self,
        scope: HTTPScope,
        receive: ASGIReceiveCallable,
        send: ASGISendCallable
    ) -> None:
        assert scope["type"] == "http"
        instance = WSGIResponder(self.app, self.executor, scope)
        await instance(receive, send)
