"""Lay out a game directory from the files the project distributes.

crimson.paq, sfx.paq and music.paq as the clients keep them: music.paq's entries
under the names the executable asks for (music\\intro.ogg, and the
music\\game_tunes.txt that brings in the official addon's tunes), as
crimson.assets_fetch.migrate_music_paq renames an earlier repack's. No
grim.dll: the module takes Grim's default font from crimson.paq
(game/resources.cpp). The checks that boot the original run from this
directory.
"""

import argparse
import urllib.request
from pathlib import Path

from crimson.assets_fetch import ASSET_BASE_URL, DEFAULT_PAQ_FILES, migrate_music_paq


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
    args.directory.mkdir(parents=True, exist_ok=True)
    for name in DEFAULT_PAQ_FILES:
        (args.directory / name).write_bytes(fetch(name, args.base))
    migrate_music_paq(args.directory)


if __name__ == "__main__":
    main()
