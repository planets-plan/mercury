import asyncio
import logging

import h11


class H11Protocol(asyncio.Protocol):

    def __init__(self, config, server_state, on_connection_lost, loop) -> None:
        if not config.loaded:
            config.load()

        self.config = config
        self.application = config.loaded_application
        self.on_connection_lost = on_connection_lost
        self.loop = loop or asyncio.get_event_loop()
        self.error_logger = logging.getLogger("mercury.server.error")
        self.access_logger = logging.getLogger("mercury.server.access")
        self.access_log = self.access_logger.hasHandlers()
        self.conn = h11.Connection
