

class LazySettings:

    def load(self):
        pass

    @property
    def is_loaded(self):
        return False


class Settings:
    pass


settings = LazySettings()
