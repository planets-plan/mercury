

from mercury.type import Any, Optional, Mapping, Iterator
from mercury.type import Scope, Receive


class Connection(Mapping[str, Any]):
    """"""

    def __init__(self, scope: Scope, receive: Optional[Receive] = None) -> None:
        assert scope["type"] in ("http", "websocket")
        self.scope = scope

    def __getitem__(self, key: str) -> Any:
        return self.scope[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.scope)

    def __len__(self) -> int:
        return len(self.scope)

    __eq__ = object.__eq__
    __hash__ = object.__hash__

