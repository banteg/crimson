from __future__ import annotations

import argparse
from pathlib import Path

import msgspec

from . import QuestCompileError, compile_quest
from .stock import stock_source


def main() -> None:
    parser = argparse.ArgumentParser(description="Compile an experimental quest recipe to a resolved JSON plan.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--stock", metavar="MAJOR.MINOR", help="compile a stock quest's DSL translation")
    source.add_argument("--file", type=Path, help="compile a .quest file")
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--players", type=int, default=1)
    parser.add_argument("--hardcore", action="store_true")
    parser.add_argument("--output", type=Path, help="write JSON here instead of stdout")
    args = parser.parse_args()
    try:
        text = stock_source(args.stock) if args.stock else args.file.read_text(encoding="utf-8")
        plan = compile_quest(text, seed=args.seed, player_count=args.players, hardcore=args.hardcore)
    except (QuestCompileError, OSError, ValueError) as exc:
        parser.error(str(exc))
    data = msgspec.json.format(msgspec.json.encode(plan)).decode() + "\n"
    if args.output:
        args.output.write_text(data, encoding="utf-8")
    else:
        print(data, end="")


if __name__ == "__main__":
    main()
