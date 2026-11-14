import re
import tomllib
from pathlib import Path

import strata

_ROOT = Path(__file__).resolve().parent.parent
_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


def test_package_version_is_semver() -> None:
    assert _SEMVER.match(strata.__version__)


def test_pyproject_uses_package_version_as_single_source() -> None:
    data = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    assert "version" not in project
    assert "version" in project["dynamic"]
    attr = data["tool"]["setuptools"]["dynamic"]["version"]["attr"]
    assert attr == "strata.__version__"


def test_cli_version_matches_package() -> None:
    from strata.cli.main import _VERSION

    assert _VERSION == strata.__version__
