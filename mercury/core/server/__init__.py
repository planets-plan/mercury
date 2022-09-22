from mercury.type import ServerConfigOptions

from mercury.utils.log import logging_init

from .server import Server, ServerHandler


__all__ = [
    "run",
    "Server",
    "ServerHandler"
]


def run(**options: ServerConfigOptions) -> None:
    logging_init(logging_config_class="logging.config.dictConfig", logging_setting_dict={})
    mercury_server = Server(**options)
    mercury_server.run()
