"""Check one candidate from stdin with the compiler the publishing CLI uses."""
from __future__ import annotations

import json
import signal
import sys

from crimson.quests.dsl import QuestCompileError, build_custom_quest


def matches(source: str, seed: int, title: str, author: str | None, digest: str) -> bool:
    try:
        compiled = build_custom_quest(source, seed=seed)
    except (QuestCompileError, RecursionError):
        return False
    # Title and author are presentation fields and excluded from the portable bytes.
    return compiled.title == title and compiled.author == author and compiled.digest() == digest


def stop_compile(_signal: int, _frame: object) -> None:
    raise TimeoutError("recipe compiler exhausted its CPU budget")


if __name__ == "__main__":
    if sys.platform == "linux":
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
        signal.signal(signal.SIGXCPU, stop_compile)
        resource.setrlimit(resource.RLIMIT_CPU, (8, 9))
    try:
        accepted = matches(**json.load(sys.stdin))
    except (TimeoutError, MemoryError):
        accepted = False
    print("verified" if accepted else "rejected")
