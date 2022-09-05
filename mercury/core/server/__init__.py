from .config import Config
from .server import Server
from .protocol.http import H11Protocol

__all__ = [
    "run",
    "Config",
    "Server",
    "H11Protocol",
]


def run(**options) -> None:
    config = Config(**options)
    server = Server(config=config)
    server.run()
