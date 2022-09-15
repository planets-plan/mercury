import sys
import inspect
import asyncio
import logging
import logging.config

from mercury.type import Dict, Literal, ServerConfigOptions
from mercury.utils.importer import import_from_string
from mercury.core.exception import ImportFromStringError
from mercury.core.server.middleware import WSGIMiddleware, ASGI2Middleware, DebugMiddleware


class Config:

    def __init__(self, **options: ServerConfigOptions) -> None:
        self.app = options.get("app")
        self.host = options["host"]
        self.port = options["port"]
        self.debug = options["debug"]
        self.reload = options["reload"]
        self.workers = options["workers"] or 1
        self.headers = options["header"]
        self.specification = options["specification"]
        self.have_server_header = options["server_header"]
        self.have_proxy_headers = options["proxy_headers"]

        self.fd = None
        self.uds = None

        self._asgi_version: Literal["2.0", "3.0"] = "3.0"
        self.ws_protocol_class = None
        self.http_protocol_class = import_from_string("mercury.core.server:H11Protocol")
        self.is_loaded = False

        self.config_logging()

    @property
    def asgi_version(self) -> Literal["2.0", "3.0"]:
        if not self.is_loaded:
            self.load()

        return self._asgi_version

    def load(self) -> None:
        assert not self.is_loaded

        encoded_headers = [
            (key.lower().encode("latin1"), value.encode("latin1"))
            for key, value in self.headers
        ]
        self.encoded_headers = (
            [(b"server", b"uvicorn")] + encoded_headers
            if b"server" not in dict(encoded_headers) and self.have_server_header
            else encoded_headers
        )

        try:
            self.loaded_app = import_from_string(self.app)
        except ImportFromStringError as e:
            # TODO logging
            sys.exit(1)

        if self.specification != "wsgi":
            if inspect.isclass(self.loaded_app):
                use_asgi_3 = hasattr(self.loaded_app, "__await__")
            elif inspect.isfunction(self.loaded_app):
                use_asgi_3 = asyncio.iscoroutinefunction(self.loaded_app)
            else:
                call = getattr(self.loaded_app, "__call__", None)
                use_asgi_3 = asyncio.iscoroutinefunction(call)
            self.specification = "asgi3" if use_asgi_3 else "asgi2"

        if self.specification == "wsgi":
            self._asgi_version = "3.0"
            self.loaded_app = WSGIMiddleware(self.loaded_app)
            self.ws_protocol_class = None
        elif self.specification == "asgi2":
            self._asgi_version = "2.0"
            self.loaded_app = ASGI2Middleware(self.loaded_app)

        if self.debug:
            self.loaded_app = DebugMiddleware(self.loaded_app)

        self.is_loaded = True

    def config_logging(self):
        DEFAULT_LOGGING = {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'mercury.server': {
                    '()': 'mercury.utils.log.ServerFormatter',
                    'format': '[{server_time}] {message}',
                    'style': '{',
                }
            },
            'handlers': {
                'console': {
                    'level': 'INFO',
                    'class': 'logging.StreamHandler',
                },
                'mercury.server': {
                    'level': 'INFO',
                    'class': 'logging.StreamHandler',
                    'formatter': 'mercury.server',
                },
            },
            'loggers': {
                'mercury': {
                    'handlers': ['console'],
                    'level': 'INFO',
                },
                'mercury.server': {
                    'handlers': ['mercury.server'],
                    'level': 'INFO',
                    'propagate': False,
                },
            }
        }
        logging.config.dictConfig(DEFAULT_LOGGING)
