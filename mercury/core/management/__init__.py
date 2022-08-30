""" The Project Management Tools for Mercury """
import sys

from typing import Union

import mercury


class ManagementUtility:

    def __init__(self, argv: Union[list[str], None] = None):
        self.argv = argv or sys.argv[:]

    def fetch_command(self, subcommand):
        pass

    def execute(self):
        try:
            subcommand = self.argv[1]
        except IndexError:
            subcommand = "help"

        parser = None

        if subcommand == "help":
            pass
        elif subcommand == "version" or self.argv[1:] == ["--version"]:
            sys.stdout.write(mercury.get_version() + "\n")
        elif self.argv[1:] in (["--help"], ["-h"]):
            sys.stdout.write("pass")
        else:
            pass


def execute_from_command_line(argv: Union[list[str], None] = None):
    utility = ManagementUtility(argv)
    utility.execute()
