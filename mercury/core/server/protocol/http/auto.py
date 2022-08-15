import asyncio
from typing import Type


AutoHTTPProtocol: Type[asyncio.Protocol]

try:
    import httptools
except ImportError:
    from mercury.core.server.protocol.http.h11 import H11Protocol
    AutoHTTPProtocol = H11Protocol
else:
    from mercury.core.server.protocol.http.httptool import HTTPToolProtocol
    AutoHTTPProtocol = HTTPToolProtocol
