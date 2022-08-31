from argparse import ArgumentParser

from mercury.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Create a Mercury project directory."
    missing_args_message = "You must provide a project name."

    def add_arguments(self, parser: ArgumentParser):
        parser.add_argument("name", help="Name of the application or project.")
        parser.add_argument("directory", nargs="?", help="Optional destination directory")

    def handle(self, *args, **options):
        self.stdout.write("hello, world")
        project_name = options.pop("name")
        target = options.pop("directory")
        self.stdout.write(project_name)
        self.stdout.write(target)
