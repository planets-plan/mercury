from mercury.type import ServerConfigOptions

from mercury.core.server import run


async def app(scope, receive, send):
    body = "Hello, world!".encode("utf-8")
    raw_headers = []
    content_length = str(len(body))
    raw_headers.append((b"content-length", content_length.encode("latin-1")))
    content_type = "text/plain"
    raw_headers.append((b"content-tpye", content_type.encode("latin-1")))
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": raw_headers,
        }
    )

    await send({"type": "http.response.body", "body": body})


if __name__ == "__main__":
    options: ServerConfigOptions = {
        "app": app,
        "host": "127.0.0.1",
        "port": 9999,
        "debug": False,
        "reload": False,
        "worker_number": 1,
        "headers": [],
        "server_header": False,
        "proxy_headers": False,
        "specification": "asgi"
    }
    run(**options)
