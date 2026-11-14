"""Fail fast when the release tag and the package version disagree."""

from __future__ import annotations

import argparse
import re
import sys

from strata import __version__

_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "expected",
        nargs="?",
        help="expected version or tag (leading 'v' is stripped)",
    )
    args = parser.parse_args(argv)

    if not _SEMVER.match(__version__):
        print(f"error: package version is not semver: {__version__!r}")
        return 1

    if args.expected:
        expected = args.expected.strip().removeprefix("v")
        if expected != __version__:
            print(
                "error: version mismatch: "
                f"tag/expected={expected!r} package={__version__!r}"
            )
            return 1

    print(f"version ok: {__version__}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
