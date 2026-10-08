"""Step the game module and the verifier core through the gate's streams.

Every stream the gate replays (the bot corpus and the supported recorded fixtures)
runs through both modules in lockstep; `game_compare.mjs` compares each snapshot.
With --live, the sessions run inside the original after it loads its assets.
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from gate import CORE, ROOT, load_streams


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORE / "build/fixtures", help="Bot corpus from matrix.mjs")
    parser.add_argument("--fixtures", type=Path, default=ROOT / "tests/fixtures/replays")
    parser.add_argument("--core", type=Path, default=CORE / "build/wasm/core.wasm")
    parser.add_argument("--game", type=Path, default=CORE / "build/game/game.wasm")
    parser.add_argument(
        "--live",
        type=Path,
        help="Original game directory: run the sessions inside the original, booted with its assets",
    )
    args = parser.parse_args()
    streams, unsupported = load_streams(args.corpus, args.fixtures)
    recorded = sum(stream.recorded is not None for stream in streams)
    if not recorded or recorded == len(streams):
        raise SystemExit("Expected both the bot corpus and recorded fixtures")
    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for stream in streams:
            path = Path(tmp) / Path(stream.name).with_suffix(".rsi").name
            path.write_bytes(stream.payload)
            paths.append(str(path))
        compare = CORE / "checks/game_compare.mjs"
        live = ["--live", str(args.live)] if args.live else []
        code = subprocess.call([shutil.which("node"), str(compare), *live, str(args.core), str(args.game), *paths])
    print(f"{len(streams)} streams; {len(unsupported)} fixtures unsupported: {', '.join(sorted(unsupported))}")
    sys.exit(code)


if __name__ == "__main__":
    main()
