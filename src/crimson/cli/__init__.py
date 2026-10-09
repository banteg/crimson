from __future__ import annotations

import sys
from importlib.metadata import entry_points

import typer


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    # A development command group (crimson-re's `match`, `native`, `dbg`) runs without loading the game's
    # commands, so `crimson match ...` imports only what that group needs.
    tools = {entry_point.name: entry_point for entry_point in entry_points(group="crimson.cli")}
    if args and args[0] in tools:
        app = typer.Typer(add_completion=False)
        app.add_typer(tools[args[0]].load(), name=args[0])
    else:
        from .app import app
    app(prog_name="crimson", args=args)
