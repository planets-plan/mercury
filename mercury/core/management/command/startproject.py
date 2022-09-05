from argparse import ArgumentParser

from mercury.core.management import TemplateCommand


class Command(TemplateCommand):
    help = "Create a Mercury project directory."
    missing_args_message = "You must provide a project name."

    def add_arguments(self, parser: ArgumentParser):
        parser.add_argument("name", help="Name of the application or project.")
        parser.add_argument("directory", nargs="?", help="Optional destination directory")

    def handle(self, *args, **options):
        name = options.pop("name")
        target = options.pop("directory")

        super().handle("project", name=name, target=target, **options)
