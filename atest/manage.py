#!/usr/bin/env python
""" Mercury's command-line utility for administrative tasks. """
import os
import sys


def main():
    """ Run administrative tasks. """
    os.environ.setdefault("MERCURY_SETTING_MODULE", "{{}}.settings")
    try:
        from mercury.core.management import execute_from_command_line
    except ImportError as e:
        raise ImportError(
            "Couldn't import Mercury. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from e

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
