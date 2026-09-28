from __future__ import annotations

from importlib.metadata import entry_points

from tqdm import tqdm

from . import replay as _replay
from . import root as _root

app = _root.app
replay_app = _replay.replay_app

app.add_typer(replay_app, name="replay")
# Development tools (the crimson-re workspace package) add their command groups here.
for entry_point in entry_points(group="crimson.cli"):
    app.add_typer(entry_point.load(), name=entry_point.name)


def _replay_render_progress_runtime(*, total_ticks: int, render_audio: bool):
    return _replay._replay_render_progress_runtime(
        total_ticks=total_ticks,
        render_audio=render_audio,
        tqdm_factory=tqdm,
    )

def main(argv: list[str] | None = None) -> None:
    app(prog_name="crimson", args=argv)
