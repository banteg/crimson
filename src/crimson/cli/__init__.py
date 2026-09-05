from __future__ import annotations

from tqdm import tqdm

from . import dbg as _dbg
from . import match as _match
from . import native as _native
from . import replay as _replay
from . import root as _root

app = _root.app
replay_app = _replay.replay_app
dbg_app = _dbg.dbg_app
match_app = _match.match_app
native_app = _native.native_app

app.add_typer(replay_app, name="replay")
app.add_typer(dbg_app, name="dbg")
app.add_typer(match_app, name="match")
app.add_typer(native_app, name="native")


def _replay_render_progress_runtime(*, total_ticks: int, render_audio: bool):
    return _replay._replay_render_progress_runtime(
        total_ticks=total_ticks,
        render_audio=render_audio,
        tqdm_factory=tqdm,
    )

def main(argv: list[str] | None = None) -> None:
    app(prog_name="crimson", args=argv)
