"""Before publishing a client, check that production reads and ranks its recordings."""

import json
import runpy
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
CAPABILITIES = "https://crimson.land/api/replay-capabilities"


def require_reader(capabilities, version: int, rules: int) -> None:
    if version not in capabilities["formats"] or rules not in capabilities["rules"]:
        raise ValueError(f"Deploy the service that accepts replay format {version} and rules {rules} before publishing")


if __name__ == "__main__":
    writer = runpy.run_path(str(ROOT / "src/crimson/game_version.py"))
    request = Request(CAPABILITIES, headers={"Cache-Control": "no-cache", "User-Agent": "crimsonland-release"})
    with urlopen(request, timeout=30) as response:
        require_reader(json.load(response), writer["REPLAY_FORMAT_VERSION"], writer["REPLAY_RULES"])
