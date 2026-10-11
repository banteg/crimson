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
# Enter takes over and plays at once; Escape pauses; Retry (from the cursor at
# 232,374) plays again from the anchor; Watch the original (232,406) returns.
SCRIPT = (
    "1:move 512 384;610:key 1c;620:unkey 1c;640:move 800 300;"
    "645:key c8;645:press 0;700:key 1;710:unkey 1;710:unkey c8;710:release 0;"
    "720:move 232 374;725:press 0;730:release 0;"
    "780:key 1;790:unkey 1;800:move 232 406;805:press 0;810:release 0;820:move 512 384"
)
TAKE, RETRY = range(605, 625), range(720, 745)


def pixels(path: Path) -> bytearray:
    header, size, depth, data = path.read_bytes().split(b"\n", 3)
    assert (header, size, depth) == (b"P6", b"1024 768", b"255")
    assert len(data) == 1024 * 768 * 3
    return bytearray(data)


def same_world(a: Path, b: Path, *, cursors: tuple[tuple[int, int], ...] = ((512, 384),)) -> None:
    images = [pixels(a), pixels(b)]
    # The viewer's bar differs; the human cursor animates between frames.
    boxes = [(0, 720, 1024, 768), *((x - 80, y - 80, x + 96, y + 96) for x, y in cursors)]
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
            "CRIMSON_CAPTURE_FRAMES": ",".join(map(str, (600, *TAKE, 680, *RETRY, 840))),
            "CRIMSON_WATCH": "practice.crd",
            "CRIMSON_WATCH_SEEK": "10800",
            "CRIMSON_WATCH_STOP": "10800",
            "CRIMSON_INPUT": SCRIPT,
            "CRIMSON_MUTE": "1",
        }
        subprocess.run([str(binary), str(game)], env=env, check=True, timeout=90)

        def state(frame: int) -> dict:
            return json.loads((captures / f"frame_{frame}.json").read_text())

        def started(frames: range) -> int:
            # The first frame playing from the anchor: it shows the anchor itself.
            frame = next(f for f in frames if state(f)["practice_state"] == 1)
            assert state(frame)["practice_ticks"] == 0, state(frame)
            return frame

        assert state(600)["practice_state"] == 0
        assert state(680)["practice_state"] == 1 and state(680)["practice_ticks"] > 0, state(680)
        assert state(RETRY[0])["practice_state"] == 2, state(RETRY[0])
        assert state(840)["practice_state"] == 0 and state(840)["watch_tick"] == 10800, state(840)
        take, retry = started(TAKE), started(RETRY)
        same_world(captures / f"frame_{take}.ppm", captures / f"frame_{retry}.ppm", cursors=((512, 384), (232, 374)))
        same_world(captures / "frame_600.ppm", captures / "frame_840.ppm")
        print(json.dumps({"takeover": True, "retry_pixels": True, "original_pixels": True}))


if __name__ == "__main__":
    main()
