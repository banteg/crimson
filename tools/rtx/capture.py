"""Capture many replay ticks in one continuous playback per build/render mode.

    uv run python tools/rtx/capture.py --game /path/to/game --replay run.crd \
        --ticks 490,494,500 --modes classic,rtx --out /tmp/comparison

Inclusive ranges are accepted: --ticks 490:500:2. Add --before-client /path/to/old/crimson
to compare builds. Each client must support CRIMSON_CAPTURE_TICKS. PNG frames and a
manifest are written beneath <out>/<build>/<mode>; logs and original PPMs are retained.
The replay seeks once before the first tick, then maintains rendering history through
all requested ticks. --history sets that initial warmup (default 240 ticks).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
CLIENT = ROOT / "crimson-core/build/app/crimson"


def parse_ticks(value: str) -> list[int]:
    ticks: set[int] = set()
    try:
        for item in value.split(","):
            parts = [int(p) for p in item.split(":")]
            if len(parts) == 1:
                ticks.add(parts[0])
            elif len(parts) in (2, 3):
                start, end = parts[:2]
                step = parts[2] if len(parts) == 3 else 1
                if start > end or step < 1 or (end - start) // step > 10000:
                    raise ValueError
                ticks.update(range(start, end + 1, step))
            else:
                raise ValueError
        if not ticks or min(ticks) < 2 or len(ticks) > 10000:
            raise ValueError
    except ValueError as exc:
        raise argparse.ArgumentTypeError("use ticks >= 2 or inclusive start:end[:step] ranges (up to 10000 frames)") from exc
    return sorted(ticks)


def capture_replay(*, game: Path, replay: Path, ticks: list[int], client: Path, mode: str,
                   out: Path, history: int = 240, timeout: float = 600) -> dict:
    """One client launch, one initial seek, every requested tick; fail on missing output."""
    if mode not in ("classic", "rtx") or history < 1 or not ticks or ticks != sorted(set(ticks)) or ticks[0] < 2:
        raise ValueError("invalid mode, history, or ascending unique ticks")
    game, replay, client, out = (p.resolve() for p in (game, replay, client, out))
    digest = hashlib.sha256(replay.read_bytes()).hexdigest()
    mounted = game / "replays" / "capture" / f"{digest}.crd"
    mounted.parent.mkdir(parents=True, exist_ok=True)
    if not mounted.exists():
        shutil.copyfile(replay, mounted)
    out.mkdir(parents=True, exist_ok=True)
    # Never allow stale frames to masquerade as a successful capture.
    for tick in ticks:
        for suffix in ("ppm", "png"):
            (out / f"tick_{tick}.{suffix}").unlink(missing_ok=True)
    (out / "manifest.json").unlink(missing_ok=True)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("CRIMSON_CAPTURE", "CRIMSON_WATCH", "CRIMSON_PROFILE")) and k != "CRIMSON_INPUT"}
    env.update(CRIMSON_CAPTURE=str(out), CRIMSON_CAPTURE_TICKS=",".join(map(str, ticks)),
               CRIMSON_WATCH=mounted.relative_to(game).as_posix(), CRIMSON_WATCH_WINDOW=str(history),
               CRIMSON_WATCH_CACHE="1", CRIMSON_RTX="1" if mode == "rtx" else "0", CRIMSON_MUTE="1")
    log_path = out / "client.log"
    try:
        with log_path.open("w") as log:
            subprocess.run([str(client), str(game)], env=env, stdout=log, stderr=subprocess.STDOUT, timeout=timeout, check=True)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Replay capture failed; see {log_path}") from exc
    sizes = []
    for tick in ticks:
        with Image.open(out / f"tick_{tick}.ppm") as image:
            sizes.append(image.size)
            image.save(out / f"tick_{tick}.png")
    manifest = {"replay": str(replay), "sha256": digest, "client": str(client), "mode": mode,
                "ticks": ticks, "history": history, "sizes": sizes, "continuous": True}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--game", required=True, type=Path)
    parser.add_argument("--replay", required=True, type=Path)
    parser.add_argument("--ticks", required=True, type=parse_ticks)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--client", type=Path, default=CLIENT)
    parser.add_argument("--before-client", type=Path)
    parser.add_argument("--modes", default="rtx", help="classic, rtx, or classic,rtx")
    parser.add_argument("--history", type=int, default=240)
    parser.add_argument("--timeout", type=float, default=600)
    args = parser.parse_args()
    modes = args.modes.split(",")
    if any(m not in ("classic", "rtx") for m in modes) or len(set(modes)) != len(modes) or args.history < 1:
        parser.error("choose unique classic/rtx modes and positive history")
    clients = {"before": args.before_client, "after": args.client} if args.before_client else {"current": args.client}
    for label, client in clients.items():
        for mode in modes:
            out = args.out / label / mode
            capture_replay(game=args.game, replay=args.replay, ticks=args.ticks, client=client, mode=mode,
                           out=out, history=args.history, timeout=args.timeout)
            print(f"{label}/{mode}: {len(args.ticks)} frames → {out}", flush=True)


if __name__ == "__main__":
    main()
