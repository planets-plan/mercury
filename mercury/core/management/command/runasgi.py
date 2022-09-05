from argparse import ArgumentParser

from mercury.core.server import run
from mercury.core.management import BaseCommand, ParserYesNoAction


class Command(BaseCommand):
    help = "Start a ASGI Application by a Mercury Server."
    missing_args_message = "You must provide a project name."

    def add_arguments(self, parser: ArgumentParser):
        parser.add_argument("app")
        parser.add_argument("--host", type=str, nargs="?", default="127.0.0.1", help="Bind socket to this host.")
        parser.add_argument("--port", type=int, nargs="?", default=8000, help="Bind socket to this port.")
        parser.add_argument("--debug", type=bool, nargs="?", default=False, help="Enable debug mode.")
        parser.add_argument("--reload", type=bool, nargs="?", default=False, help="Enable auto-reload.")
        parser.add_argument("--workers", type=int, nargs="?", default=None, help="Number of worker process.")
        parser.add_argument("--header", type=str, nargs="*", default=[], required=False, help="Specify custom default HTTP response headers as a Name:Value pair.")
        parser.add_argument("--server-header", action=ParserYesNoAction, default=True, help="Enable/Disable default Server header.")
        parser.add_argument("--proxy-headers", action=ParserYesNoAction, default=True, help="Enable/Disable X-Forwarded-Proto, X-Forwarded-For, X-Forwarded-Port to populate remote address info.")

    def handle(self, *args, **options):
        options["specification"] = "asgi"
        run(**options)
