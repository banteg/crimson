from __future__ import annotations

from importlib.metadata import entry_points

from . import replay as _replay
from . import root as _root

app = _root.app
replay_app = _replay.replay_app

app.add_typer(replay_app, name="replay")
# Development tools (the crimson-re workspace package) add their command groups here.
for entry_point in entry_points(group="crimson.cli"):
    app.add_typer(entry_point.load(), name=entry_point.name)


def main(argv: list[str] | None = None) -> None:
    app(prog_name="crimson", args=argv)
