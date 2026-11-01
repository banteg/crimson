"""Prepare only the artwork, levels and audio shipped with the selected freeware release."""

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

ARCHIVES = {
    "1.0.2": {"crimson.paq": "b12f5f362b3b1d9541fcf7c169f348d5bd739e1903cc98281e5f60699adba9f7"},
    "1.3.0": {"crimson.paq": "9515a1e4ccee9815b38a79ee4960c224729ff82a09fd5b0c81f69c8d2c603fc3",
              "tiles.paq": "859181f5fe885b7243f0531ea18c3922f62c8d759e7857468e98866015eb2171"},
    "1.4.0": {"crimson.paq": "31f5ba92dbcc2460a3962a77fa266b92d41be9b1c69b84e8350a56ec7f37e84a",
              "sounds.paq": "a82a59f40749e009dca3f9cb934a073e7a67bb11415da0e3ca1766c9059ff11b"},
}
LOOSE_SOUNDS = {
    "1.0.2": "444810304396cab168d2153275ad02755bc45ab053ded6cb10142c1de689ae44",
    "1.3.0": "ea3a56900cb9103b9edd4576903a68fc8c9939877bec1bf61436b5ce8e089d6d",
}


def loose_files(folder: Path, extensions: set[str], expected: str) -> dict[str, Path]:
    files = {p.name.lower(): p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in extensions}
    entries = [name + ":" + hashlib.sha256(p.read_bytes()).hexdigest() for name, p in sorted(files.items())]
    if hashlib.sha256("\n".join(entries).encode()).hexdigest() != expected:
        raise SystemExit(f"{folder} does not match the original distribution")
    return files


def prepare(root: Path, install: Path, out: Path, edition: str = "1.4.0") -> None:
    registry = json.loads((root / "decomp/builds.json").read_text())
    build = next(build for build in registry["builds"] if build["id"] == edition)
    for name, digest in ARCHIVES[edition].items():
        if hashlib.sha256((install / name).read_bytes()).hexdigest() != digest:
            raise SystemExit(f"{install / name} does not match the original {edition} package")
    grim = (install / "grim.dll").read_bytes()
    expected = next(image["sha256"] for image in build["images"] if image["name"] == "grim.dll")
    if hashlib.sha256(grim).hexdigest() != expected:
        raise SystemExit(f"{install} does not contain the original {edition} grim.dll")
    with pefile.PE(data=grim) as pe:
        resources = next(entry for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries if entry.id == 10)
        font = next(entry for entry in resources.directory.entries if entry.id == 111)
        data = font.directory.entries[0].data.struct
        font_tga = pe.get_data(data.OffsetToData, data.Size)
    out.mkdir(parents=True, exist_ok=True)
    textures = dict(read_paq(install / "crimson.paq"))
    if edition == "1.0.2":
        del textures["crimsonland.tg_"]  # Unused alternate title, alongside crimsonland.tga.
    if edition == "1.3.0":
        textures.update(read_paq(install / "tiles.paq"))
        levels = loose_files(install / "levels", {".lvl"}, "06f07cb7399ff8f4af29f1f4b53e98bebf251f4ad0de07d3843c0737dd30c157")
        (out / "levels").mkdir(exist_ok=True)
        for name, path in levels.items():
            shutil.copyfile(path, out / "levels" / name)
    textures["font.tga"] = font_tga
    names = []
    for name, raw in textures.items():
        if Path(name).name != name or Path(name).suffix.lower() not in {".tga", ".jpg"}:
            raise ValueError(f"unexpected graphics entry {name!r}")
        stem = Path(name).stem.lower()
        with Image.open(BytesIO(raw)) as image:
            payload = struct.pack("<II", *image.size) + image.convert("RGBA").tobytes()
        (out / (stem + ".rgba")).write_bytes(payload)
        names.append(stem)
    (out / "textures.txt").write_text("\n".join(names) + "\n")
    if edition in LOOSE_SOUNDS:
        sounds = loose_files(install / "sounds", {".wav", ".mp3"}, LOOSE_SOUNDS[edition])
        for name, path in sounds.items():
            if name.endswith(".wav"):
                shutil.copyfile(path, out / name)
        tracks = [path for name, path in sounds.items() if name.endswith(".mp3")]
    else:
        for name, raw in read_paq(install / "sounds.paq"):
            if Path(name).name != name or Path(name).suffix.lower() != ".wav":
                raise ValueError(f"unexpected sound entry {name!r}")
            (out / name.lower()).write_bytes(raw)
        tracks = [install / "music" / (name + ".mp3") for name in ("alqvol", "3cwonder", "survo41")]
    for track in tracks:
        ffmpeg = shutil.which("ffmpeg")
        if not ffmpeg:
            raise SystemExit("ffmpeg is required to prepare the original MP3 tracks")
        subprocess.run([ffmpeg, "-nostdin", "-v", "error", "-y", "-i", track, "-fflags", "+bitexact",
                        "-flags:a", "+bitexact", "-map_metadata", "-1", "-c:a", "vorbis", "-strict",
                        "experimental", "-b:a", "192k", out / (track.stem.lower() + ".ogg")], check=True)
