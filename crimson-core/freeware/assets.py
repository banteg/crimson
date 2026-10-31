"""Prepare the 1.4.0 artwork and sound samples for either client from its original install."""

import hashlib
import json
import shutil
import struct
import subprocess
from io import BytesIO
from pathlib import Path

import pefile
from PIL import Image

from grim.paq import read_paq


def prepare(root: Path, install: Path, out: Path) -> None:
    registry = json.loads((root / "decomp/builds.json").read_text())
    build = next(build for build in registry["builds"] if build["id"] == "1.4.0")
    # These archives belong to the pinned freeware package, apart from the later Classic repack.
    for name, digest in (
        ("crimson.paq", "31f5ba92dbcc2460a3962a77fa266b92d41be9b1c69b84e8350a56ec7f37e84a"),
        ("sounds.paq", "a82a59f40749e009dca3f9cb934a073e7a67bb11415da0e3ca1766c9059ff11b"),
    ):
        if hashlib.sha256((install / name).read_bytes()).hexdigest() != digest:
            raise SystemExit(f"{install / name} does not match the original 1.4.0 package")
    grim = (install / "grim.dll").read_bytes()
    expected = next(image["sha256"] for image in build["images"] if image["name"] == "grim.dll")
    if hashlib.sha256(grim).hexdigest() != expected:
        raise SystemExit(f"{install} does not contain the original 1.4.0 grim.dll")
    with pefile.PE(data=grim) as pe:
        resources = next(entry for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries if entry.id == 10)
        font = next(entry for entry in resources.directory.entries if entry.id == 111)
        data = font.directory.entries[0].data.struct
        font_tga = pe.get_data(data.OffsetToData, data.Size)
    out.mkdir(parents=True, exist_ok=True)
    for name, raw in [*read_paq(install / "crimson.paq"), ("font.tga", font_tga)]:
        if Path(name).name != name or Path(name).suffix.lower() != ".tga":
            raise ValueError(f"unexpected graphics entry {name!r}")
        with Image.open(BytesIO(raw)) as image:
            # Decode once at build time. Both renderers receive identical straight-alpha RGBA.
            payload = struct.pack("<II", *image.size) + image.convert("RGBA").tobytes()
        (out / (Path(name).stem.lower() + ".rgba")).write_bytes(payload)
    for name, raw in read_paq(install / "sounds.paq"):
        if Path(name).name != name or Path(name).suffix.lower() != ".wav":
            raise ValueError(f"unexpected sound entry {name!r}")
        (out / name.lower()).write_bytes(raw)
    # Use the Vorbis decoder already shipped by the classic game module.
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise SystemExit("ffmpeg is required to prepare the original MP3 tracks")
    for track in ("alqvol", "3cwonder", "survo41"):
        subprocess.run(
            [
                ffmpeg,
                "-nostdin",
                "-v",
                "error",
                "-y",
                "-i",
                install / "music" / f"{track}.mp3",
                "-fflags",
                "+bitexact",
                "-flags:a",
                "+bitexact",
                "-map_metadata",
                "-1",
                "-c:a",
                "vorbis",
                "-strict",
                "experimental",
                "-b:a",
                "192k",
                out / f"{track}.ogg",
            ],
            check=True,
        )
