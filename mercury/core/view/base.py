from mercury.type import List, Optional, Literal


HTTP_METHODS = List[Literal["get", "post", "put", "patch", "delete", "head", "options", "trace"]]


class View:
    allow_http_methods: HTTP_METHODS = ["get", "post", "put", "patch", "delete", "head", "options", "trace"]

    pass
