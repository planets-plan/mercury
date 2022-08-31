from typing import Optional, Literal
from argparse import ArgumentParser

from mercury.core.management.base import BaseCommand, CommandError


class TemplateCommand(BaseCommand):

    def add_arguments(self, parser: ArgumentParser):
        parser.add_argument("name", help="Name of the application of project, required.")
        parser.add_argument("directory", nargs="?", help="Destination directory, optional.")

    def validate_name(self, name: str, name_type: Literal["file", "path"]) -> None:
        if name is None:
            raise CommandError(f"Must provide {'an' if self.template_type == 'app' else 'a'} {self.template_type} name")

        if not name.isidentifier():
            raise CommandError(f"{name} is not a valid {self.template_type} {name_type}. Please make sure the {name_type} is is a valid identified.")


    def handle(
        self,
        template_type: Literal[""],
        name: str,
        target: Optional[str] = None,
        **options
    ) -> None:
        self.template_type = template_type
        pass
