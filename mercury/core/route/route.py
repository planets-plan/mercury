

class Route:
    def __init__(self):
        pass


class RoutePattern:

    def match(self, path: str):
        raise NotImplementedError()

    def describe(self):
        description = f"'{self}'"
        if self.name:
            description += f" [name='{self.name}']"
        return description


class RouteResolver:
    """ Route """

    def __init__(self, pattern, callback, default_args=None, name=None) -> None:
        self.pattern = pattern
        self.callback = callback
        self.default_args = default_args
        self.name = name

    def resolve(self, path):
        match = self.pattern.match(path)
        if match:
            new_path, args, captured_kwargs = match
            kwargs = {**captured_kwargs, **self.default_args}
            return None
