from mercury.core.view import View, ViewSet


class Response:
    pass


async def test(request):
    return Response()


class TestView(View):

    def get(self, request):
        pass


class TestViewSet(ViewSet):

    def list(self, request):
        pass


async def app(scope, receive, send):
    import json
    # import pprint
    # pprint.pp(scope)
    with open("test.txt", "a+") as f:
        f.write(str(scope))
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
