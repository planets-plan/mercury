from uvicorn import run

from mercury.core.application import Application


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
    run()