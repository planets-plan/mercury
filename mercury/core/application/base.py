from mercury.type import Any


class Application:
    """ Mercury Application """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def load_middleware(self):
        self._view_middleware = []
        self._template_middle = []
        self._exception_middle = []

    def get_view(self, request):
        """ Get view by request """
        pass


