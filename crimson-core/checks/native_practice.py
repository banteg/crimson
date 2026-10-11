"""Exercise real native practice buttons and compare restored world/HUD pixels.

python3 crimson-core/checks/native_practice.py <native binary> [asset directory]
Linux CI runs this under Xvfb. Captures stay in a temporary directory.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    "1:move 512 384;610:key 1c;620:unkey 1c;640:move 800 300;"
    "645:key c8;645:press 0;700:key 1;710:unkey 1;710:unkey c8;710:release 0;"
    "720:move 232 374;725:press 0;730:release 0;745:move 512 384;"
    "780:key 1;790:unkey 1;800:move 232 406;805:press 0;810:release 0;820:move 512 384"
)


def pixels(path: Path) -> bytearray:
    header, size, depth, data = path.read_bytes().split(b"\n", 3)
    assert (header, size, depth) == (b"P6", b"1024 768", b"255")
    assert len(data) == 1024 * 768 * 3
    return bytearray(data)


def same_world(a: Path, b: Path, *, ready: bool) -> None:
    images = [pixels(a), pixels(b)]
    # Viewer/practice bands differ; the human cursor animates between frames.
    boxes = [(0, 720, 1024, 768), (432, 304, 608, 480)]
    if ready:
        boxes.append((367, 343, 657, 427))
    for data in images:
        for left, top, right, bottom in boxes:
            for y in range(top, bottom):
                start, end = (y * 1024 + left) * 3, (y * 1024 + right) * 3
                data[start:end] = bytes(end - start)
    assert images[0] == images[1], f"world or HUD differs: {a.name} / {b.name}"


def main() -> None:
    binary = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="crimson-native-practice-") as folder:
        root = Path(folder)
        game, captures = root / "game", root / "captures"
        game.mkdir()
        captures.mkdir()
        for name in ("crimson.paq", "sfx.paq", "music.paq"):
            if len(sys.argv) > 2:
                source = Path(sys.argv[2]) / name
                if name == "music.paq" and not source.exists():
                    shutil.copytree(source.parent / "music", game / "music")
                else:
                    shutil.copy2(source, game / name)
            else:
                request = urllib.request.Request(
                    f"https://paq.crimson.banteg.xyz/v1.9.93/{name}",
                    headers={"User-Agent": "crimsonland-decompile"},
                )
                with urllib.request.urlopen(request, timeout=60) as source:
                    (game / name).write_bytes(source.read())
        shutil.copy2(ROOT / "tests/fixtures/replays/survival-238852.crd", game / "practice.crd")
        env = {
            **os.environ,
            "CRIMSON_CAPTURE": str(captures),
            "CRIMSON_CAPTURE_FRAMES": "600,630,680,720,750,800,840",
            "CRIMSON_WATCH": "practice.crd",
            "CRIMSON_WATCH_SEEK": "10800",
            "CRIMSON_WATCH_STOP": "10800",
            "CRIMSON_INPUT": SCRIPT,
            "CRIMSON_MUTE": "1",
        }
        subprocess.run([str(binary), str(game)], env=env, check=True, timeout=90)
        for frame, phase in ((600, 0), (630, 1), (680, 2), (720, 3), (750, 1), (800, 3), (840, 0)):
            state = json.loads((captures / f"frame_{frame}.json").read_text())
            assert state["watch_tick"] == 10800
            assert state["practice_state"] == phase, (frame, state)
            if phase == 1 or frame == 840:
                assert state["practice_ticks"] == 0
            if phase == 2:
                assert state["practice_ticks"] > 0
        same_world(captures / "frame_630.ppm", captures / "frame_750.ppm", ready=True)
        same_world(captures / "frame_600.ppm", captures / "frame_840.ppm", ready=False)
        print(json.dumps({"takeover": True, "retry_pixels": True, "original_pixels": True}))


if __name__ == "__main__":
    main()
