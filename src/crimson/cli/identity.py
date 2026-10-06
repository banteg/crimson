from __future__ import annotations

from pathlib import Path

import typer

from ..paths import default_runtime_dir

identity_app = typer.Typer(add_completion=False, help="The leaderboard key this game signs ranked runs with.")

_BASE_DIR = typer.Option(
    default_runtime_dir(),
    "--base-dir",
    "--runtime-dir",
    help="base path for runtime files (default: per-user OS data dir; override with CRIMSON_RUNTIME_DIR)",
)


@identity_app.command("show")
def cmd_identity_show(base_dir: Path = _BASE_DIR) -> None:
    """Print the public key and the fingerprint the boards show for it, making the key on first use."""
    from ..leaderboard import Identity

    identity = Identity.load_or_create(base_dir)
    typer.echo(f"public key:  {identity.public_key.hex()}")
    typer.echo(f"fingerprint: {identity.fingerprint}")


@identity_app.command("export")
def cmd_identity_export(
    path: Path = typer.Argument(..., help="file to write the private key to; keep it secret"),
    base_dir: Path = _BASE_DIR,
) -> None:
    """Copy the private key to a file, to move it to another machine."""
    from ..leaderboard import Identity

    if path.exists():
        raise typer.BadParameter(f"{path} already exists")
    Identity.load_or_create(base_dir).save(path)
    typer.echo(f"exported to {path}")


@identity_app.command("import")
def cmd_identity_import(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, help="a key written by `crimson identity export`"),
    base_dir: Path = _BASE_DIR,
    replace: bool = typer.Option(False, "--replace", help="overwrite this game's own key"),
) -> None:
    """Make this game sign as an exported key."""
    from ..leaderboard import Identity, IdentityError
    from ..leaderboard.identity import IDENTITY_FILE

    try:
        identity = Identity.load(path)
    except IdentityError as exc:
        raise typer.BadParameter(str(exc)) from exc
    target = base_dir / IDENTITY_FILE
    if target.exists() and not replace:
        current = Identity.load(target)
        if current.public_key != identity.public_key:
            raise typer.BadParameter(f"{target} holds another key ({current.fingerprint}); pass --replace to overwrite it")
    target.parent.mkdir(parents=True, exist_ok=True)
    identity.save(target)
    typer.echo(f"imported key {identity.fingerprint}")
