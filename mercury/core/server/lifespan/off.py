

class LifespanOff:
    def __init__(self) -> None:
        self.should_exit = False

    async def startup(self) -> None:
        pass

    async def shutdown(self) -> None:
        pass
