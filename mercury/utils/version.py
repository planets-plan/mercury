import datetime
import functools
import subprocess

from pathlib import Path
from typing import Tuple, Optional

VERSION = Tuple[int, int, int, str, int]


def get_complete_version(version: VERSION = None):
    if version is None:
        from mercury import VERSION as version
    else:
        assert len(version) == 5
        assert version[3] in ("alpha", "beta", "rc", "final")

    return version


def get_main_version(version: VERSION = None):
    version = get_complete_version(version)
    parts = 2 if version[2] == 0 else 3
    return ".".join(str(x) for x in version[:parts])


@functools.lru_cache
def get_git_change_time() -> Optional[str]:
    repo_dir = Path(".").parent.parent.absolute()
    git_log = subprocess.run(
        "git log --pretty=format:%ct --quiet -1 HEAD",
        capture_output=True,
        shell=True,
        cwd=repo_dir,
        text=True
    )
    timestamp = git_log.stdout
    tz = datetime.timezone.utc
    try:
        timestamp = datetime.datetime.fromtimestamp(int(timestamp), tz=tz)
    except ValueError:
        return None
    return timestamp.strftime("%Y%m%d%H%M%S")


def get_version(version: VERSION = None) -> str:
    """ Return a PEP 440-compliant version number from VERSION. """
    version = get_complete_version(version)

    main = get_main_version(version)

    sub = ""
    if version[3] == "alpha" and version[4] == 0:
        git_change_time = get_git_change_time()
        if git_change_time:
            sub = f".dev{git_change_time}"
    elif version[3] != "final":
        mapping = {"alpha": "a", "beta": "b", "rc": "rc"}
        sub = mapping[version[3]] + str(version[4])

    return main + sub
