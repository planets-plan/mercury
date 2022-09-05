from argparse import ArgumentParser

from mercury.core.management.base import BaseCommand, ParserYesNoAction


class Command(BaseCommand):

    def add_arguments(self, parser: ArgumentParser):
        parser.add_argument("app")
        parser.add_argument("-h", "--host", type=str, default="127.0.0.1", help="Bind socket to this host.")
        parser.add_argument("-p", "--port", type=int, default=8000, help="Bind socket to this port.")
        parser.add_argument("-d", "--debug", type=bool, default=False, help="Enable debug mode.")
        parser.add_argument("-r", "--reload", type=bool, default=False, help="Enable auto-reload.")
        parser.add_argument("-w", "--workers", type=int, default=None, help="Number of worker process.")
        parser.add_argument("--header", type=str, nargs="*", required=False, help="Specify custom default HTTP response headers as a Name:Value pair.")
        parser.add_argument("--server-header", action=ParserYesNoAction, help="Enable/Disable default Server header.")
        parser.add_argument("--proxy-headers", action=ParserYesNoAction, help="Enable/Disable X-Forwarded-Proto, X-Forwarded-For, X-Forwarded-Port to populate remote address info.")

    def handle(self, *args, **options) -> None:
        pass
