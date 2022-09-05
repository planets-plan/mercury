from mercury.core.management.template import TemplateCommand


class Command(TemplateCommand):
    help = (
        "Creates a Mercury application directory structure for the given name in "
        "the current directory or optionally in the given directory."
    )
    missing_args_message = "You must provide an application name."

    def handle(self, **options) -> None:
        name = options.pop("name")
        target = options.pop("directory")
        super().handle("app", name=name, target=target, **options)
