import logging.config

from .importer import import_from_string


DEFAULT_LOGGING_CONFIG = {}


def logging_init(logging_config, logging_setting):
    if logging_config:
        # TODO maybe need other import function
        logging_config_func = import_from_string(logging_config)
        logging.config.dictConfig(DEFAULT_LOGGING_CONFIG)

        if logging_setting:
            logging_config_func(logging_setting)
