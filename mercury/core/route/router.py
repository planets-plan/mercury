from mercury.type import Optional


class BaseRouter:

    def __init__(self):
        self.registry = []

    def register(self, prefix, viewset, basename: Optional[str] = None) -> None:
        pass

    def get_default_basename(self, viewset) -> None:
        raise NotImplementedError()

    def get_routes(self) -> None:
        raise NotImplementedError()


class Router(BaseRouter):
    pass

