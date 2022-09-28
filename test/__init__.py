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


from fastapi import FastAPI

app2 = FastAPI()


@app2.get("/")
async def root():
    return {"message": "Hello World"}

@app2.get("/apple")
async def root2():
    return {"message": "Hello Apple"}


if __name__ == "__main__":
    options: ServerConfigOptions = {
        "app": app2,
        "host": "127.0.0.1",
        "port": 8888,
        "debug": False,
        "reload": False,
        "worker_number": 1,
        "headers": [],
        "server_header": False,
        "proxy_headers": False,
        "specification": "asgi"
    }
    run(**options)
