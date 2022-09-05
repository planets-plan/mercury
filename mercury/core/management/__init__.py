""" The Project Management Tools for Mercury """
import sys
import pkgutil
import functools

from typing import Optional
from pathlib import Path
from importlib import import_module

import mercury
from mercury.conf import settings

from .base import BaseCommand, ParserYesNoAction
from .template import TemplateCommand


__all__ = [
    "BaseCommand",
    "TemplateCommand",
    "ParserYesNoAction",
    "execute_from_command_line"
]


def find_commands(management_dir: Path) -> list[str]:
    commands_dir = management_dir / "command"
    return [
        name
        for _, name, is_pkg in pkgutil.iter_modules([str(commands_dir.absolute())])
        if not is_pkg and not name.startswith("_")
    ]


@functools.lru_cache(maxsize=None)
def get_commands() -> dict:
    commands = {name: "mercury.core" for name in find_commands(Path(__file__).parent)}

    if not settings.is_loaded:
        return commands

    return {}


def load_command_class(app_name: str, subcommand: str) -> BaseCommand:
    module = import_module(f"{app_name}.management.command.{subcommand}")

    if hasattr(module, "Command"):
        return module.Command()
    else:
        pass


class ManagementUtility:

    def __init__(self, argv: Optional[list[str]] = None):
        self.argv = argv or sys.argv[:]

    def fetch_command(self, subcommand: str):
        """ Try to fetch the given subcommand """
        commands = get_commands()

        try:
            app_name = commands[subcommand]
        except KeyError:
            sys.exit(1)

        if isinstance(app_name, BaseCommand):
            klass = None
        else:
            klass = load_command_class(app_name, subcommand)

        return klass

    def execute(self) -> None:
        try:
            subcommand = self.argv[1]
        except IndexError:
            subcommand = "help"

        if subcommand == "help":
            pass
        elif subcommand == "version" or self.argv[1:] == ["--version"]:
            sys.stdout.write(mercury.get_version() + "\n")
        elif self.argv[1:] in (["--help"], ["-h"]):
            sys.stdout.write("pass")
        else:
            self.fetch_command(subcommand).run_from_argv(self.argv)


def execute_from_command_line(argv: Optional[list[str]] = None):
    utility = ManagementUtility(argv)
    utility.execute()
