import importlib

from typing import Any

from mercury.core.exception import ImportFromStringError


def import_from_string(import_str: str) -> Any:
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
