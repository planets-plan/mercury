import os
import socket
import logging
import asyncio
import functools
import sys
import threading
import signal

from types import FrameType

from mercury.type import Set, List, Tuple, Optional, Sequence
from mercury.core.server.config import Config
from mercury.core.server.lifespan import LifespanOn, LifespanOff


logger = logging.getLogger("mercury.error")

HANDLED_SIGNALS = (
    signal.SIGINT,  # Unix signal 2. Sent by Ctrl+C.
    signal.SIGTERM,  # Unix signal 15. Sent by `kill <pid>`.
)


class ServerState:
    def __init__(self) -> None:
        self.total_requests = 0
        self.connections: Set[asyncio.Protocol] = set()
        self.tasks: Set[asyncio.Task] = set()
        self.default_headers: List[Tuple[bytes, bytes]] = []


class Server:

    def __init__(self, config: Config) -> None:
        self.config = config
        self.server_state = ServerState()

        self.started = False
        self.should_exit = False
        self.force_exit = False
        self.last_notified = 0.0

    def run(self, sockets: Optional[List[socket.socket]] = None) -> None:
        return asyncio.run(self.server(sockets=sockets))

    async def server(self, sockets: Optional[List[socket.socket]] = None) -> None:
        process_id = os.getpid()

        config = self.config
        if not config.is_loaded:
            config.load()

        if config.specification != "wsgi":
            self.lifespan = LifespanOff()
        else:
            self.lifespan = LifespanOn(config)

        self.install_signal_handlers()

        logger.info(f"Start server process [{process_id}]")

        await self.startup(sockets=sockets)
        if self.should_exit:
            return
        await self.main_loop()
        await self.shutdown(sockets=sockets)

        logger.info(f"Finished server process [{process_id}]")

    async def on_tick(self, counter: int) -> bool:
        if counter % 10 == 0:
            self.server_state.default_headers = self.config.encoded_headers

        if self.should_exit:
            return True
        return False

    async def main_loop(self) -> None:
        counter = 0
        should_exit = await self.on_tick(counter)
        while not should_exit:
            counter += 1
            counter = counter % 864000
            await asyncio.sleep(0.1)
            should_exit = await self.on_tick(counter)

    def _log_started_message(self, listeners: Sequence[socket.SocketType]) -> None:
        config = self.config

        if config.fd is not None:
            pass
        elif config.uds is not None:
            pass
        else:
            host = "0.0.0.0" if config.host is None else config.host

            port = config.port
            if port == 0:
                port = listeners[0].getsockname()[1]

            protocol_name = "http"

            message = f"MercuryServer running on {protocol_name}://{host}:{port} (Press CTRL+C to quit)"
            logger.info(message)

    async def startup(self, sockets: Optional[List] = None) -> None:
        await self.lifespan.startup()
        if self.lifespan.should_exit:
            self.should_exit = True
            return

        config = self.config

        protocol = functools.partial(
            config.http_protocol_class, config=config, server_state=self.server_state
        )
        loop = asyncio.get_running_loop()

        listeners: Sequence[socket.SocketType]
        if sockets is not None:
            pass
        elif config.fd is not None:
            pass
        elif config.uds is not None:
            pass
        else:
            try:
                server = await loop.create_server(
                    protocol,
                    host=config.host,
                    port=config.port,
                    ssl=None,
                    backlog=2048,
                )
            except OSError as e:
                logger.error(e)
                await self.lifespan.shutdown()
                sys.exit(1)

            assert server.sockets is not None
            listeners = server.sockets
            self.servers = [server]

        if sockets is None:
            self._log_started_message(listeners)
        else:
            pass

        self.started = True

    async def shutdown(self, sockets: Optional[List] = None) -> None:
        logger.info("Shutting down...")

        for server in self.servers:
            server.close()
        for sock in sockets or []:
            sock.close()
        for server in self.servers:
            await server.wait_closed()

        for connection in list(self.server_state.connections):
            connection.shutdown()
        await asyncio.sleep(0.1)

    def install_signal_handlers(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            # Signals can only be listened to from the main thread.
            return

        loop = asyncio.get_event_loop()

        try:
            for sig in HANDLED_SIGNALS:
                loop.add_signal_handler(sig, self.handle_exit, sig, None)
        except NotImplementedError:  # pragma: no cover
            # Windows
            for sig in HANDLED_SIGNALS:
                signal.signal(sig, self.handle_exit)

    def handle_exit(self, sig: int, frame: Optional[FrameType]) -> None:

        if self.should_exit and sig == signal.SIGINT:
            self.force_exit = True
        else:
            self.should_exit = True
