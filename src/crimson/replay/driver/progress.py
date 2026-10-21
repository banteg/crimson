"""Terminal progress for replay tools; reports remain on stdout."""

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TimeElapsedColumn, TimeRemainingColumn


def replay_progress(*, enabled: bool) -> Progress:
    return Progress(
        "[progress.description]{task.description}",
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=Console(stderr=True),
        transient=True,
        disable=not enabled,
    )
