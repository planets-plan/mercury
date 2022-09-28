import logging
import logging.config

from mercury.type import Optional
from mercury.utils.terminal_color import color_style, colorize

from .importer import import_string


DEFAULT_LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {},
    "formatters": {
        "mercury.server": {
            "()": "mercury.utils.log.ServerFormatter",
            "format": "[{server_time}] | [{levelname}] | {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "level": "INFO",
            "filters": [],
            "class": "logging.StreamHandler",
        },
        "mercury.server.error": {
            "level": "INFO",
            "class": "logging.StreamHandler",
            "formatter": "mercury.server",
            "stream": "ext://sys.stderr"
        },
        "mercury.server.access": {
            "level": "INFO",
            "class": "logging.StreamHandler",
            "formatter": "mercury.server",
            "stream": "ext://sys.stdout"
        },
    },
    "loggers": {
        "mercury": {
            "handlers": ["console"],
            "level": "INFO"
        },
        "mercury.server.error": {
            "level": "INFO",
            "handlers": ["mercury.server.error"],
            "propagate": False,
        },
        "mercury.server.access": {
            "level": "INFO",
            "handlers": ["mercury.server.access"],
            "propagate": False,
        },
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
    level_color_dict = {
        "INFO": "green",
        "ERROR": "red",
        "WARNING": "yellow",
    }

    def __init__(self, *args, **kwargs):
        self.style = color_style()
        super().__init__(*args, **kwargs)

    def uses_server_time(self):
        return self._fmt.find("{server_time}") >= 0

    def uses_levelname(self):
        return self._fmt.find("{levelname}") >= 0

    def format(self, record: logging.LogRecord) -> str:
        msg = record.msg
        if self.uses_server_time() and not hasattr(record, "server_time"):
            record.server_time = self.formatTime(record, self.datefmt)

        if self.uses_levelname() and hasattr(record, "levelname"):
            record.levelname = colorize(f'{record.levelname}', fg=self.level_color_dict.get(record.levelname, "green"))

        record.msg = msg
        return super().format(record)
