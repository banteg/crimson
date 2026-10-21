from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import typer

from ..paths import default_runtime_dir

save_app = typer.Typer(add_completion=False, help="Manage campaign progress in game.cfg.")


def _backup_save(path: Path) -> Path:
    backup_path: Path | None = None
    try:
        with path.open("rb") as source, tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=f"{path.name}.", suffix=".bak", delete=False,
        ) as backup:
            backup_path = Path(backup.name)
            shutil.copyfileobj(source, backup)
            backup.flush()
            os.fsync(backup.fileno())
    except OSError:
        if backup_path is not None:
            backup_path.unlink(missing_ok=True)
        raise
    return backup_path


@save_app.command("unlock")
def cmd_save_unlock(
    base_dir: Path = typer.Option(
        default_runtime_dir(),
        "--base-dir",
        "--runtime-dir",
        help="base path for runtime files (default: per-user OS data dir; override with CRIMSON_RUNTIME_DIR)",
    ),
) -> None:
    """Unlock every normal and hardcore quest, backing up the existing save first. Close the game before running."""
    from ..persistence.save_status import GAME_CFG_NAME, load_status
    from ..quests.level import QUEST_COUNT

    path = base_dir / GAME_CFG_NAME
    try:
        status = load_status(path)
    except FileNotFoundError as exc:
        typer.echo(f"No save at {path}. Start the game once or pass --base-dir with an existing save.", err=True)
        raise typer.Exit(code=1) from exc
    except (OSError, ValueError) as exc:
        typer.echo(f"Could not read save {path}: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if status.quest_unlock_index == QUEST_COUNT and status.quest_unlock_index_hardcore == QUEST_COUNT:
        typer.echo(f"Already fully unlocked: {path}")
        return

    try:
        backup_path = _backup_save(path)
    except OSError as exc:
        typer.echo(f"Could not back up save {path}: {exc}. Save was not changed.", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Backup: {backup_path}")
    status.quest_unlock_index = QUEST_COUNT
    status.quest_unlock_index_hardcore = QUEST_COUNT
    try:
        status.save()
    except OSError as exc:
        typer.echo(f"Could not write save {path}: {exc}. Backup preserved at {backup_path}.", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Unlocked all {QUEST_COUNT} normal and hardcore quests: {path}")
