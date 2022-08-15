from mercury.type import Scope, Receive, Send, ASGIApp


class Application:

    def __init__(self, func):

        async def application(scope: Scope, receive: Receive, send: Send) -> None:
            response = await func(None)
            await response(scope, receive, send)

        self.application: ASGIApp = application

    async def __call__(self, scope, receive, send) -> None:
        await self.application(scope, receive, send)
