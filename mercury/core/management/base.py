from argparse import ArgumentParser


class BaseCommand:
    """ CLI """

    def __init__(self):
        pass

    def add_arguments(self, parser):
        pass

    def handle(self, *args, **options):
        raise NotImplementedError("subclass of BaseCommand must provide a handle() method")
