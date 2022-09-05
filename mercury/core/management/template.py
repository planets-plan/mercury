import os
import stat
import shutil

from argparse import ArgumentParser
from importlib import import_module
from typing import Optional, Literal
from pathlib import Path

import mercury
from mercury.conf import settings
from mercury.core.management.base import BaseCommand, CommandError


class TemplateCommand(BaseCommand):
    rewrite_template_suffixes = (
        (".py-tpl", ".py"),
    )

    def add_arguments(self, parser: ArgumentParser):
        parser.add_argument("name", help="Name of the application of project, required.")
        parser.add_argument("directory", nargs="?", help="Destination directory, optional.")

    def validate_name(self, name: str, name_type: Literal["file", "path"] = "name") -> None:
        if name is None:
            raise CommandError(f"Must provide {self.pre} {self.template_type} name")

        if not name.isidentifier():
            raise CommandError(f"{name} is not a valid {self.template_type} {name_type}. Please make sure the {name_type} is is a valid identified.")

        try:
            import_module(name)
        except ImportError:
            pass
        else:
            raise CommandError(f"'{name}' conflicts with the name of an existing Python module and cannot be use as {self.pre} {self.template_type} {name_type}. Please try another {name_type}.")

    def apply_umask(self, old_path: str, new_path: str) -> None:
        current_umask = os.umask(0)
        os.umask(current_umask)
        current_mode = stat.S_IMODE(os.stat(old_path).st_mode)
        os.chmod(new_path, current_mode & ~current_umask)

    def make_writeable(self, filepath: str) -> None:
        if not os.access(filepath, os.W_OK):
            st = os.stat(filepath)
            new_permissions = stat.S_IMODE(st.st_mode) | stat.S_IWUSR
            os.chmod(filepath, new_permissions)

    def handle(
        self,
        template_type: Literal["app", "project"],
        name: str,
        target: Optional[str] = None,
        **options
    ) -> None:
        self.pre = 'an' if template_type == 'app' else 'a'
        self.template_type = template_type
        self.verbosity = options["verbosity"]

        self.validate_name(name)

        if target is None:
            top_dir = Path(os.getcwd()) / name
            try:
                os.makedirs(top_dir)
            except FileExistsError:
                raise CommandError(f"'{top_dir.absolute()}' already exists.")
            except OSError as e:
                raise CommandError(e)
        else:
            top_dir = (Path(os.getcwd()) / name).absolute()
            if template_type == "app":
                self.validate_name(top_dir.name, "path")
            if not top_dir.exists():
                raise CommandError(f"Destination directory '{top_dir}' does not exist, please create it first.")

        if not settings.is_loaded:
            settings.load()

        template_dir = Path(mercury.__path__[0]) / "template" / f"{template_type}_template"
        prefix_length = len(str(template_dir)) + 1

        for root, dirs, files in os.walk(template_dir):
            sub_dir = root[prefix_length:]

            if sub_dir:
                os.makedirs(top_dir / sub_dir)

            for dirname in dirs:
                if dirname.startswith(".") or dirname == "__pycache__":
                    dirs.remove(dirname)

            for filename in files:
                if filename.endswith((".pyo", ".pyc", ".py.class")):
                    # Ignore some files as they cause various breakages.
                    continue

                old_path = str((Path(root) / filename).absolute())
                new_path = str((top_dir / sub_dir / filename).absolute())

                for old_suffix, new_suffix in self.rewrite_template_suffixes:
                    if new_path.endswith(old_suffix):
                        new_path = new_path[: -len(old_suffix)] + new_suffix
                        break

                if os.path.exists(new_path):
                    raise CommandError(
                        f"{new_path} already exists. Overlaying {self.pre} {template_type} into an existing "
                        "directory won't replace conflicting files."
                    )

                shutil.copyfile(old_path, new_path)

                if self.verbosity >= 2:
                    self.stdout.write(f"Creating {new_path}")

                try:
                    self.apply_umask(old_path, new_path)
                    self.make_writeable(new_path)
                except OSError:
                    self.stderr.write(
                        f"Notice: Couldn't set permission bits on {new_path}. You're "
                        "probably using an uncommon filesystem setup. No problem.",
                        self.style.NOTICE
                    )


