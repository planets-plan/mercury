import pathlib

from setuptools import Extension
from Cython.Build import cythonize

ROOT = pathlib.Path(__file__).parent

ext_modules = [
    Extension(
        name="mercury.core.server.protocol.http.parser",
        sources=[
            "mercury/core/server/protocol/http/parser/parser.pyx",
            "mercury/core/server/protocol/http/parser/llhttp/api.c",
            "mercury/core/server/protocol/http/parser/llhttp/http.c",
            "mercury/core/server/protocol/http/parser/llhttp/llhttp.c",
        ],
        extra_compile_args=["-O2"],
        include_dirs=[
            str(ROOT / "mercury" / "core" / "server" / "protocol" / "http" / "parser"),
            str(ROOT / "mercury" / "core" / "server" / "protocol" / "http" / "parser" / "llhttp"),
        ],
    )
]


def build(setup_kwargs):
    setup_kwargs.update(ext_modules=cythonize(ext_modules))
