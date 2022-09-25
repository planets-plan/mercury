import asyncio

from mercury.type import TYPE_CHECKING

if TYPE_CHECKING:
    from mercury.core.server.server import Server
    from mercury.type import (
        LifespanScope,
        LifespanSendMessage,
        LifespanStartupEvent,
        LifespanShutdownEvent,
        LifespanReceiveMessage,
    )


__all__ = ["Lifespan", "LifespanOn", "LifespanOff"]


STATE_TRANSITION_ERROR = "Got invalid state transition on lifespan protocol."


class Lifespan:
    def __init__(self) -> None:
        self.should_exit = False

    async def startup(self) -> None:
        raise NotImplementedError()

    async def shutdown(self) -> None:
        raise NotImplementedError()


class LifespanOff(Lifespan):
    def __init__(self) -> None:
        super().__init__()

    async def startup(self) -> None:
        pass

    async def shutdown(self) -> None:
        pass


class LifespanOn(Lifespan):

    def __init__(self, server: "Server") -> None:
        super().__init__()
        self.server = server

        self.startup_event = asyncio.Event()
        self.shutdown_event = asyncio.Event()
        self.receive_queue: asyncio.Queue[LifespanReceiveMessage] = asyncio.Queue()
        self.error_occured = False
        self.startup_failed = False
        self.shutdown_failed = False

    async def _main(self) -> None:
        try:
            application = self.server.loaded_app
            scope: LifespanScope = {
                "type": "lifespan",
                "asgi": {"version": self.server.asgi_version, "spec_version": "2.0"},
            }
            await application(scope, self.receive, self.send)
        except BaseException as e:
            self.asgi = None
            self.error_occured = True
            if self.startup_failed or self.shutdown_failed:
                return
            if self.server.specification == "wsgi":
                self.server.logger.info("ASGI 'lifespan' protocol appears unsupported.")
            else:
                self.server.logger.error("Exception in 'lifespan' protocol\n", exc_info=e)
        finally:
            self.startup_event.set()
            self.shutdown_event.set()

    async def startup(self) -> None:
        self.server.logger.info("Waiting for application startup.")

        loop = asyncio.get_running_loop()
        lifespan_main_task = loop.create_task(self._main())  # noqa: F841 | Keep a hard reference to prevent garbage collection

        startup_event: LifespanStartupEvent = {"type": "lifespan.startup"}
        await self.receive_queue.put(startup_event)
        await self.startup_event.wait()

        if self.startup_failed or (self.error_occured and self.server.specification == "asgi"):
            self.server.logger.error("Application startup failed. Exiting.")
            self.should_exit = True
        else:
            self.server.logger.info("Application startup complete.")

    async def shutdown(self) -> None:
        if self.error_occured:
            return

        self.server.logger.info("Waiting for application shutdown.")

        shutdown_event: LifespanShutdownEvent = {"type": "lifespan.shutdown"}
        await self.receive_queue.put(shutdown_event)
        await self.shutdown_event.wait()

        if self.shutdown_failed or (self.error_occured and self.server.specification == "asgi"):
            self.server.logger.error("Application shutdown failed. Exiting.")
            self.should_exit = True
        else:
            self.server.logger.info("Application shutdown complete.")

    def on_startup_complete(self) -> None:
        assert not self.startup_event.is_set(), STATE_TRANSITION_ERROR
        assert not self.shutdown_event.is_set(), STATE_TRANSITION_ERROR

        self.startup_event.set()

    def on_startup_failed(self, message: "LifespanSendMessage") -> None:
        assert not self.startup_event.is_set(), STATE_TRANSITION_ERROR
        assert not self.shutdown_event.is_set(), STATE_TRANSITION_ERROR

        self.startup_event.set()
        self.startup_failed = True

        if message.get("message"):
            self.server.logger.error(message["message"])

    def on_shutdown_complete(self) -> None:
        assert not self.startup_event.is_set(), STATE_TRANSITION_ERROR
        assert not self.shutdown_event.is_set(), STATE_TRANSITION_ERROR
        self.shutdown_event.set()

    def on_shutdown_failed(self, message: "LifespanSendMessage") -> None:
        assert not self.startup_event.is_set(), STATE_TRANSITION_ERROR
        assert not self.shutdown_event.is_set(), STATE_TRANSITION_ERROR

        self.shutdown_event.set()
        self.shutdown_failed = True

        if message.get("message"):
            self.server.logger.error(message["message"])

    async def send(self, message: "LifespanSendMessage") -> None:
        assert message["type"] in (
            "lifespan.startup.complete",
            "lifespan.startup.failed",
            "lifespan.shutdown.complete",
            "lifespan.shutdown.failed",
        )

        if message["type"] == "lifespan.startup.complete":
            self.on_startup_complete()
        elif message["type"] == "lifespan.startup.failed":
            self.on_startup_failed(message)
        elif message["type"] == "lifespan.shutdown.complete":
            self.on_shutdown_complete()
        elif message["type"] == "lifespan.shutdown.failed":
            self.on_shutdown_failed(message)

    async def receive(self) -> "LifespanReceiveMessage":
        return await self.receive_queue.get()
