import sys
import os.path
import argparse

from io import TextIOBase, TextIOWrapper
from typing import Any, Sequence, Optional, TypedDict
from argparse import Action, Namespace, HelpFormatter, ArgumentParser

import mercury
from mercury.core.management.color import no_style, color_style


class ParserOptions(TypedDict):
    prog: Optional[str]
    usage: Optional[str]
    description: Optional[str]
    epilog: Optional[str]
    parents: Optional[list[ArgumentParser]]
    formatter_class: Optional[HelpFormatter]
    prefix_chars: Optional[str]
    fromfile_prefix_chars: Optional[str]
    argument_default: Optional[str]
    conflict_handler: Optional[str]
    add_help: Optional[bool]
    allow_abbrev: Optional[bool]
    exit_on_error: Optional[bool]


class CommandError(Exception):

    def __init__(self, *args: Any, returncode: int = 1, **kwargs: Any):
        self.returncode = returncode
        super().__init__(*args, **kwargs)


class ParserYesNoAction(Action):
    def __init__(
        self,
        option_strings: Sequence[str],
        dest: str,
        required: bool = False,
        help: Optional[str] = None,
        default: Optional[str] = None,
    ) -> None:
        if default is None:
            raise ValueError("You must provide a default with Yes/No action.")
        if len(option_strings) != 1:
            raise ValueError("Only single argument is allowed with Yes/No action.")

        opt = option_strings[0]
        if not opt.startswith("--"):
            raise ValueError("Yes/No arguments must be prefixed with --.")

        opt = opt[2:]
        opts = ["--" + opt, "--no-" + opt]
        super(ParserYesNoAction, self).__init__(opts, dest, nargs=0, const=None, default=default, required=required, help=help)

    def __call__(
            self,
            parser: ArgumentParser,
            namespace: Namespace,
            values: Any,
            option_string: Optional[str] = None
    ) -> None:
        if option_string.startswith("--no-"):
            setattr(namespace, self.dest, False)
        else:
            setattr(namespace, self.dest, True)


class CommandParser(ArgumentParser):

    def __init__(
        self,
        *,
        missing_args_message: Optional[str] = None,
        called_from_command_line: Optional[bool] = None,
        **kwargs: Any
    ):
        self.missing_args_message = missing_args_message
        self.called_from_command_line = called_from_command_line
        super().__init__(**kwargs)

    def parse_args(
        self,
        args: Optional[list[str]] = None,
        namespace: Optional[str] = None
    ) -> Namespace:
        if self.missing_args_message and not (args or any(not arg.startswith("-") for arg in args)):
            self.error(self.missing_args_message)
        return super().parse_args(args, namespace)

    def error(self, message: str) -> None:
        if self.called_from_command_line:
            super().error(message)
        else:
            raise CommandError(f"Error: {message}")


class OutputWrapper(TextIOBase):

    def __init__(self, out, ending="\n") -> None:
        self._out = out
        self.style_func = None
        self.ending = ending

    def __getattr__(self, name: str) -> Any:
        return getattr(self._out, name)

    @property
    def style_func(self):
        return self._style_func

    @style_func.setter
    def style_func(self, style_func):
        if style_func and self.isatty():
            self._style_func = style_func
        else:
            self._style_func = lambda x: x

    def flush(self) -> None:
        if hasattr(self._out, "flush"):
            self._out.flush()

    def isatty(self) -> bool:
        return hasattr(self._out, "isatty") and self._out.isatty()

    def write(self, msg: Optional[str] = "", style_func: Optional[Any] = None, ending: Optional[str] = None):
        msg = str(msg)
        ending = self.ending if ending is None else ending

        if ending and not msg.endswith(ending):
            msg += ending

        style_func = style_func or self.style_func

        self._out.write(style_func(msg))


class MercuryHelpFormatter(HelpFormatter):
    """
    Customized formatter so that command-specific arguments appear in the
    --help output before arguments common to all commands.
    """

    show_last = {
        "--version",
        "--verbosity",
        "--traceback",
        "--settings",
        "--pythonpath",
        "--no-color",
        "--force-color",
        "--skip-checks",
    }

    def _reordered_actions(self, actions):
        return sorted(
            actions, key=lambda a: set(a.option_strings) & self.show_last != set()
        )

    def add_usage(self, usage, actions, *args, **kwargs):
        super().add_usage(usage, self._reordered_actions(actions), *args, **kwargs)

    def add_arguments(self, actions):
        super().add_arguments(self._reordered_actions(actions))


class BaseCommand:
    """ CLI """
    help = ""
    _called_from_command_line: bool = False

    suppressed_base_arguments = set()

    def __init__(
        self,
        stdout: Optional[TextIOWrapper] = None,
        stderr: Optional[TextIOWrapper] = None,
        no_color: Optional[bool] = False,
        force_color: Optional[bool] = False
    ):
        self.stdout: OutputWrapper = OutputWrapper(stdout or sys.stdout)
        self.stderr: OutputWrapper = OutputWrapper(stderr or sys.stderr)

        if no_color and force_color:
            raise CommandError("'no_color' and 'force_color' can't be used together.")

        if no_color:
            self.style = no_style()
        else:
            self.style = color_style(force_color)
            self.stderr.style_func = self.style.ERROR

        # TODO
        # if (
        #     not isinstance(self.requires_system_checks, (list, tuple))
        #     and self.requires_system_checks != ALL_CHECKS
        # ):
        #     raise TypeError("requires_system_checks must be a list or tuple.")

    def get_version(self):
        return mercury.get_version()

    def add_arguments(self, parser: ArgumentParser):
        pass

    def add_base_argument(self, parser, *args, **kwargs):
        for arg in args:
            if arg in self.suppressed_base_arguments:
                kwargs["help"] = argparse.SUPPRESS
                break
        parser.add_argument(*args, **kwargs)

    def create_parser(self, prog_name: str, subcommand: str, **kwargs: Any) -> CommandParser:
        kwargs.setdefault("formatter_class", MercuryHelpFormatter)
        parser = CommandParser(
            prog=f"{os.path.basename(prog_name)} {subcommand}",
            description=self.help or None,
            missing_args_message=getattr(self, "missing_args_message", None),
            called_from_command_line=getattr(self, "_called_from_command_line", None),
            **kwargs,
        )
        self.add_base_argument(
            parser,
            "--version",
            action="version",
            version=self.get_version(),
            help="Show program's version number and exit."
        )
        self.add_base_argument(
            parser,
            "-v",
            "--verbosity",
            default=1,
            type=int,
            choices=[0, 1, 2, 3],
            help=(
                "Verbosity level; 0=minimal output, 1=normal output, 2=verbose output, "
                "3=very verbose output"
            ),
        )
        self.add_base_argument(
            parser,
            "--no-color",
            action="store_true",
            help="Don't colorize the command output.",
        )
        self.add_base_argument(
            parser,
            "--force-color",
            action="store_true",
            help="Force colorization of the command output.",
        )
        self.add_arguments(parser)
        return parser

    def run_from_argv(self, argv: list[str]):
        self._called_from_command_line = True

        parser = self.create_parser(argv[0], argv[1])

        options = parser.parse_args(argv[2:])
        cmd_options = vars(options)
        args = cmd_options.pop("args", ())

        try:
            self.execute(*args, **cmd_options)
        except CommandError as e:
            self.stderr.write(f"{e.__class__.__name__}: {e}")
            sys.exit(e.returncode)
        finally:
            pass

    def execute(self, *args, **options):
        if options["force_color"] and options["no_color"]:
            raise CommandError(
                "The --no-color and --force-color options can't be used together."
            )
        if options["force_color"]:
            self.style = color_style(force_color=True)
        elif options["no_color"]:
            self.style = no_style()
            self.stderr.style_func = None
        if options.get("stdout"):
            self.stdout = OutputWrapper(options["stdout"])
        if options.get("stderr"):
            self.stderr = OutputWrapper(options["stderr"])

        output = self.handle(*args, **options)
        if output:
            self.stdout.write(output)

        return output

    def handle(self, *args, **options) -> None:
        raise NotImplementedError("subclass of BaseCommand must provide a handle() method")
