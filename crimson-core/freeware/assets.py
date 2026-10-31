"""Prepare the 1.4.0 artwork and sound samples for either client from its original install."""

import hashlib
import json
import struct
from io import BytesIO
from pathlib import Path

import pefile
from PIL import Image

from grim.paq import read_paq


def prepare(root: Path, install: Path, out: Path) -> None:
    registry = json.loads((root / "decomp/builds.json").read_text())
    build = next(build for build in registry["builds"] if build["id"] == "1.4.0")
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
