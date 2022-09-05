from . import List, Tuple, Union, Literal, Optional, Callable, TypedDict
from . import ASGIApplication


__all__ = ["LoopType", "SpecificationType", "ServerConfigOptions"]

LoopType = Literal["none", "auto", "asyncio", "uvloop"]
SpecificationType = Literal["auto", "asgi", "wsgi"]


class ServerConfigOptions(TypedDict):
    app: Union[ASGIApplication, Callable, str]
    host: str
    port: int
    debug: bool
    reload: bool
    workers: Optional[int]
    headers: List[Tuple[str, str]]
    server_header: bool
    proxy_headers: bool
    specification: Optional[SpecificationType]
