"""Check native asset preparation against a directory containing the shipped PAQs."""

import argparse
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

from game_files import fetch, paq_entries

from crimson.assets_fetch import ASSET_BASE_URL

CLIENT = Path(__file__).resolve().parents[1] / "client"
PROBE = """
#include <stdio.h>
#include <string>
std::string client_prepare_assets(const std::string &directory);
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  const auto error = client_prepare_assets(argv[1]);
  if (!error.empty()) { fprintf(stderr, "%s\\n", error.c_str()); return 1; }
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?", help="PAQ directory; otherwise download the shipped files")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        archives = args.directory
        if archives is None:
            archives = root / "archives"
            archives.mkdir()
            for name in ("crimson.paq", "sfx.paq", "music.paq"):
                (archives / name).write_bytes(fetch(name, ASSET_BASE_URL))
        source, probe = root / "probe.cpp", root / "probe"
        source.write_text(PROBE)
        flags = shlex.split(
            subprocess.check_output([shutil.which("pkg-config"), "--cflags", "--libs", "sdl3"], text=True),
        )
        libdir = subprocess.check_output([shutil.which("pkg-config"), "--variable=libdir", "sdl3"], text=True).strip()
        rpath = f"-Wl,-rpath,{libdir}"
        if rpath not in flags:
            flags.append(rpath)
        subprocess.run(
            [shutil.which("clang++"), "-std=c++17", str(CLIENT / "assets.cpp"), str(source), *flags, "-o", str(probe)],
            check=True,
        )
        game = root / "game"
        game.mkdir()
        for name in ("crimson.paq", "sfx.paq"):
            shutil.copyfile(archives / name, game / name)
        missing = subprocess.run([str(probe), str(game)], capture_output=True, text=True, check=False)
        if missing.returncode != 1 or "Missing music/intro.ogg" not in missing.stderr:
            raise ValueError(f"Missing music was not reported: {missing}")
        shutil.copyfile(archives / "music.paq", game / "music.paq")
        expected = {
            name.replace("\\", "/").split("/")[-1]: data
            for name, data in paq_entries((game / "music.paq").read_bytes())
        }
        subprocess.run([str(probe), str(game)], check=True)
        if {file.name: file.read_bytes() for file in (game / "music").iterdir()} != expected:
            raise ValueError("Unpacked music differs from the archive")
        # Repair a partial extraction and preserve an existing, customized track.
        (game / "music/intro.ogg").unlink()
        custom = expected["crimson_theme.ogg"]
        (game / "music/shortie_monk.ogg").write_bytes(custom)
        subprocess.run([str(probe), str(game)], check=True)
        if (game / "music/intro.ogg").read_bytes() != expected["intro.ogg"]:
            raise ValueError("The missing track was not restored")
        if (game / "music/shortie_monk.ogg").read_bytes() != custom:
            raise ValueError("An existing track was overwritten")
        # Archive output must not follow links out of the selected folder.
        for existing in (False, True):
            outside = root / f"outside-{existing}.ogg"
            if existing:
                outside.write_bytes(custom)
            track = game / "music/intro.ogg"
            track.unlink()
            track.symlink_to(outside)
            linked = subprocess.run([str(probe), str(game)], capture_output=True, text=True, check=False)
            if outside.exists() != existing or (existing and outside.read_bytes() != custom):
                raise ValueError("Extraction wrote through a linked music file")
            if linked.returncode != 1:
                raise ValueError("A linked music file was accepted")
            track.unlink()
            subprocess.run([str(probe), str(game)], check=True)
        music = game / "music"
        saved = root / "saved-music"
        music.rename(saved)
        outside_directory = root / "outside-music"
        outside_directory.mkdir()
        music.symlink_to(outside_directory, target_is_directory=True)
        linked = subprocess.run([str(probe), str(game)], capture_output=True, text=True, check=False)
        if list(outside_directory.iterdir()):
            raise ValueError("Extraction wrote through a linked music folder")
        if linked.returncode != 1:
            raise ValueError("A linked music folder was accepted")
        music.unlink()
        saved.rename(music)
        # Match the runtime's case-insensitive names on case-sensitive disks.
        for name in ("sfx.paq", "music.paq", "crimson.paq"):
            (game / name).rename(game / name.upper())
            subprocess.run([str(probe), str(game)], check=True)
        for track in music.iterdir():
            track.rename(track.with_name(track.name.upper()))
        music.rename(game / "MUSIC")
        subprocess.run([str(probe), str(game)], check=True)
        (game / "MUSIC/INTRO.OGG").unlink()
        subprocess.run([str(probe), str(game)], check=True)
        if (game / "MUSIC/intro.ogg").read_bytes() != expected["intro.ogg"]:
            raise ValueError("Mixed-case music folder was not repaired")
        if sorted(file.name.lower() for file in (game / "MUSIC").iterdir()) != sorted(expected):
            raise ValueError("Extraction created duplicate tracks with different case")
        (game / "MUSIC.PAQ").unlink()
        subprocess.run([str(probe), str(game)], check=True)
        (game / "MUSIC").rename(music)
        for track in music.iterdir():
            track.rename(track.with_name(track.name.lower()))
        for name in ("crimson.paq", "sfx.paq"):
            (game / name.upper()).rename(game / name)
        # Original installations with loose music need no archive.
        subprocess.run([str(probe), str(game)], check=True)
        (game / "music/crimsonquest.ogg").unlink()
        missing = subprocess.run([str(probe), str(game)], capture_output=True, text=True, check=False)
        if missing.returncode != 1 or "Missing music/crimsonquest.ogg" not in missing.stderr:
            raise ValueError(f"The missing loose track was not reported: {missing}")
    print("Native assets: extraction, repair, preservation, loose files, missing files and symlinks passed")


if __name__ == "__main__":
    main()
