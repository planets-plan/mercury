from asyncio import Protocol, Transport

from mercury.type import Tuple, Literal, Optional
from mercury.core.server.protocol.utils import get_local_addr, get_remote_addr, get_sslcontext


class HttpProtocol(Protocol):

    def __init__(self) -> None:
        self.transport: Optional[Transport] = None
        self.server: Optional[Tuple[str, int]] = None
        self.client: Optional[Tuple[str, int]] = None
        self.scheme: Optional[Literal["https", "http"]] = None

    def connection_made(self, transport: Transport) -> None:
        """ Overwrite asyncio.BaseProtocol.connection_made function.

        Args:
            transport:

        Returns:
            None
        """
        # TODO connections manage | flow manage
        self.transport = transport
        self.server = get_local_addr(transport)
        self.client = get_remote_addr(transport)
        self.scheme = "https" if get_sslcontext(transport) else "http"

        # TODO logging

    def connection_lost(self, exc: Optional[Exception]) -> None:
        pass

    def data_received(self, data: bytes) -> None:
        """ Overwrite asyncio.Protocol.data_received function.

        Called when some data is received. data is a non-empty bytes object
        containing the incoming data.

        Args:
            data:

        Returns:

        """
        pass

    def eof_received(self) -> Optional[bool]:
        pass

