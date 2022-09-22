import pathlib

from setuptools import Extension
from Cython.Build import cythonize

ROOT = pathlib.Path(__file__).parent

ext_modules = [
    Extension(
        name="mercury.core.server.protocol.parser.parser",
        sources=[
            "mercury/core/server/protocol/parser/parser.pyx",
            "mercury/core/server/protocol/parser/llhttp/api.c",
            "mercury/core/server/protocol/parser/llhttp/http.c",
            "mercury/core/server/protocol/parser/llhttp/llhttp.c",
        ],
        extra_compile_args=["-O2"],
        include_dirs=[
            str(ROOT / "mercury" / "core" / "server" / "protocol" / "parser" / "llhttp"),
        ],
    )
]


def build(setup_kwargs):
    setup_kwargs.update(ext_modules=cythonize(ext_modules))
