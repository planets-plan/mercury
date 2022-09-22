from . import List, Tuple, Union, Literal, Optional, Callable, TypedDict
from . import ASGIApplication


__all__ = ["LoopType", "SpecificationType", "ServerConfigOptions"]

LoopType = Literal["none", "auto", "asyncio", "uvloop"]
SpecificationType = Literal["auto", "asgi", "wsgi"]


class ServerConfigOptions(TypedDict):
    app: Union[ASGIApplication, Callable, str]
    host: Optional[str]
    port: Optional[int]
    debug: Optional[bool]
    reload: Optional[bool]
    worker_number: Optional[int]
    headers: Optional[List[Tuple[str, str]]]
    server_header: Optional[bool]
    proxy_headers: Optional[bool]
    specification: Optional[SpecificationType]
