import logging
import logging.config

from mercury.type import Optional
from mercury.utils.terminal_color import color_style

from .importer import import_string


DEFAULT_LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {},
    "formatters": {
        "mercury.server": {
            "()": "mercury.utils.log.ServerFormatter",
            "format": "[{server_time}] {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "level": "INFO",
            "filters": [],
            "class": "logging.StreamHandler",
        },
        "mercury.server": {
            "level": "INFO",
            "class": "logging.StreamHandler",
            "formatter": "mercury.server"
        },
    },
    "loggers": {
        "mercury": {
            "handlers": ["console"],
            "level": "INFO"
        },
        "mercury.server": {
            "handlers": ["mercury.server"],
            "level": "INFO",
            "propagate": False,
        },
        "mercury.server.access": {},
        "mercury.server.error": {},
    }
}


def logging_init(logging_config_class: Optional[str] = None, logging_setting_dict: Optional[dict] = None):
    if logging_config_class:
        # TODO maybe need other import function
        logging_config_func = import_string(logging_config_class)
        logging.config.dictConfig(DEFAULT_LOGGING_CONFIG)

        if logging_setting_dict:
            logging_config_func(logging_setting_dict)


class ServerFormatter(logging.Formatter):
    default_time_format = "%Y-%m-%d %H:%M:%S"

    def __init__(self, *args, **kwargs):
        self.style = color_style()
        super().__init__(*args, **kwargs)

    def uses_server_time(self):
        return self._fmt.find("{server_time}") >= 0

    def format(self, record: logging.LogRecord) -> str:
        msg = record.msg
        status_code = getattr(record, "status_code", None)

        if status_code:
            if 200 <= status_code < 300:
                # Put 2XX first, since it should be the common case
                msg = self.style.HTTP_SUCCESS(msg)
            elif 100 <= status_code < 200:
                msg = self.style.HTTP_INFO(msg)
            elif status_code == 304:
                msg = self.style.HTTP_NOT_MODIFIED(msg)
            elif 300 <= status_code < 400:
                msg = self.style.HTTP_REDIRECT(msg)
            elif status_code == 404:
                msg = self.style.HTTP_NOT_FOUND(msg)
            elif 400 <= status_code < 500:
                msg = self.style.HTTP_BAD_REQUEST(msg)
            else:
                # Any 5XX, or any other status code
                msg = self.style.HTTP_SERVER_ERROR(msg)

        if self.uses_server_time() and not hasattr(record, "server_time"):
            record.server_time = self.formatTime(record, self.datefmt)

        record.msg = msg
        return super().format(record)
