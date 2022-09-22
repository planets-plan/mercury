import sys
import importlib

from typing import Any

from mercury.core.exception import ImportFromStringError


def cached_import(module_path, class_name):
    # Check whether module is loaded and fully initialized.
    if not (
        (module := sys.modules.get(module_path))
        and (spec := getattr(module, "__spec__", None))
        and getattr(spec, "_initializing", False) is False
    ):
        module = importlib.import_module(module_path)
    return getattr(module, class_name)


def import_string(dotted_path):
    """
    Import a dotted module path and return the attribute/class designated by the
    last name in the path. Raise ImportError if the import failed.
    """
    try:
        module_path, class_name = dotted_path.rsplit(".", 1)
    except ValueError as err:
        raise ImportError("%s doesn't look like a module path" % dotted_path) from err

    try:
        return cached_import(module_path, class_name)
    except AttributeError as err:
        raise ImportError(
            'Module "%s" does not define a "%s" attribute/class'
            % (module_path, class_name)
        ) from err


def import_app_from_string(import_str: str) -> Any:
    """ Import module or module's attr by given str.

    Args:
        import_str: A string like <module>[:<attribute>].

    Returns:
        the module or module's attr

    Raises:
        ImportFromStringError
    """
    if not isinstance(import_str, str):
        return import_str

    module_str, _, attrs_str = import_str.partition(":")
    if not module_str or not attrs_str:
        raise ImportFromStringError(
            f"Import string '{import_str}' must be in format '<module>:<attribute>'."
        )

    try:
        module = importlib.import_module(module_str)
    except ImportError as e:
        if e.name != module_str:
            raise e from None

        raise ImportFromStringError(
            f"Could not import module '{module_str}'"
        )

    instance = module
    try:
        for attr_str in attrs_str.split("."):
            instance = getattr(instance, attr_str)
    except AttributeError:
        raise ImportFromStringError(
            f"Attribute '{attrs_str}' not found in module '{module_str}'."
        )

    return instance
