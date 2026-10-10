"""Fail closed when a required runtime job failed, was cancelled, or unexpectedly skipped."""

from __future__ import annotations

import argparse
import json
import os


def require(suite: str, needs: dict) -> None:
    def result(name: str, expected: str) -> None:
        actual = needs[name]["result"]
        if actual != expected:
            raise ValueError(f"{name}: expected {expected}, got {actual}")

    result("changes", "success")
    outputs = needs["changes"]["outputs"]

    def flag(name: str) -> bool:
        value = outputs[name]
        if value not in ("true", "false"):
            raise ValueError(f"{name}: invalid relevance {value!r}")
        return value == "true"

    release = flag("release")

    if suite == "core":
        python, game, oracles = (flag(name) for name in ("python", "game", "oracles"))
        if flag("core") != (python or game or oracles) or flag("corpus") != flag("core"):
            raise ValueError("inconsistent core relevance")
        checks = {
            "build-native": flag("core"),
            "corpus": flag("corpus"),
            "python": python,
            "python-report": python,
            "game-smoke": game,
            "game-parity": game,
            "oracles": oracles,
        }
        if flag("core") or release:
            result("build-wasm", "success")
        if game or release:
            result("build-game", "success")
    elif suite == "client":
        checks = {"client": flag("client") or release}
        if flag("client") or release:
            result("build-game", "success")
    elif suite == "service":
        checks = {"service": flag("service")}
        if flag("service"):
            result("build-wasm", "success")
    else:
        raise ValueError(f"unknown gate {suite}")
    for name, relevant in checks.items():
        result(name, "success" if relevant else "skipped")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", choices=("core", "client", "service"))
    args = parser.parse_args()
    require(args.suite, json.loads(os.environ["NEEDS"]))


if __name__ == "__main__":
    main()
