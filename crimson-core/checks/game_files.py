"""Lay out a game directory from the files the project distributes.

grim.dll, crimson.paq and sfx.paq as they are, and music.paq unpacked into
music/, where the executable plays its music from (the official addon's tunes
come in through music/game_tunes.txt). The checks that boot the original run
from this directory.
"""

import argparse
import struct
import urllib.request
from pathlib import Path

from crimson.assets_fetch import ASSET_BASE_URL

FILES = ("grim.dll", "crimson.paq", "sfx.paq")


def paq_entries(data):
    if data[:4] != b"paq\0":
        raise SystemExit("not a PAQ")
    offset = 4
    while offset < len(data):
        end = data.index(b"\0", offset)
        name = data[offset:end].decode("latin1")
        (size,) = struct.unpack_from("<I", data, end + 1)
        yield name, data[end + 5 : end + 5 + size]
        offset = end + 5 + size


def fetch(name, base):
    # The asset host refuses requests without a user agent.
    request = urllib.request.Request(f"{base}/{name}", headers={"User-Agent": "crimsonland-decompile"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--base", default=ASSET_BASE_URL)
    args = parser.parse_args()
    (args.directory / "music").mkdir(parents=True, exist_ok=True)
    for name in FILES:
        (args.directory / name).write_bytes(fetch(name, args.base))
    for name, data in paq_entries(fetch("music.paq", args.base)):
        (args.directory / "music" / name.split("/")[-1]).write_bytes(data)


if __name__ == "__main__":
    main()
