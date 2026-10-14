from __future__ import annotations

import base64
from pathlib import Path

import msgspec
import typer

from ..paths import default_runtime_dir

quest_app = typer.Typer(add_completion=False, help="Compile, inspect, and publish custom quest recipes (.quest).")

_BASE_DIR = typer.Option(
    default_runtime_dir(),
    "--base-dir",
    "--runtime-dir",
    help="base path for runtime files (default: per-user OS data dir; override with CRIMSON_RUNTIME_DIR)",
)


def _find_matching_clear_replay(replays_dir: Path, digest: str) -> Path | None:
    from ..replay.codec import ReplayCodecError, load_replay_file
    from ..replay.ranked import outcome_reasons, unranked_reasons

    if not replays_dir.is_dir():
        return None
    candidates = sorted(replays_dir.glob("*-quest.crd"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in candidates:
        try:
            replay = load_replay_file(path)
        except (OSError, ReplayCodecError):
            continue
        custom = replay.run.custom_quest
        if custom is None or custom.digest() != digest:
            continue
        if not unranked_reasons(replay.run) and not outcome_reasons(replay.run, replay.result):
            return path
    return None


@quest_app.command("build")
def cmd_quest_build(
    quest_file: Path = typer.Argument(..., exists=True, dir_okay=False, help="path to a .quest recipe file"),
    seed: int = typer.Option(0, "--seed", help="uint32 construction seed"),
    json_out: bool = typer.Option(False, "--json", help="print the compiled CustomQuest JSON"),
) -> None:
    """Compile and validate a .quest recipe and print its digest and entry budget."""
    from ..quests.dsl import QuestCompileError, build_custom_quest

    try:
        source = quest_file.read_text(encoding="utf-8")
        quest = build_custom_quest(source, seed=seed)
    except (OSError, QuestCompileError) as exc:
        typer.echo(f"quest build failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    digest = quest.digest()
    if json_out:
        typer.echo(msgspec.json.format(msgspec.json.encode(quest)).decode())
        return
    total_copies = sum(entry.count for entry in quest.entries)
    typer.echo(f"title:   {quest.title}" + (f" ({quest.byline})" if quest.byline else ""))
    typer.echo(f"id:      {digest[:12]} (digest {digest})")
    typer.echo(f"weapon:  {quest.start_weapon_id.name.lower()}")
    typer.echo(f"terrain: {quest.terrain_slots}")
    typer.echo(f"entries: {len(quest.entries)} / 256 ({total_copies} total copies)")


@quest_app.command("publish")
def cmd_quest_publish(
    quest_file: Path = typer.Argument(..., exists=True, dir_okay=False, help="path to a .quest recipe file"),
    replay_file: Path | None = typer.Option(
        None,
        "--replay",
        exists=True,
        dir_okay=False,
        help="completed ranked .crd replay of this quest (default: newest matching clear in replays/)",
    ),
    seed: int = typer.Option(0, "--seed", help="uint32 construction seed"),
    name: str | None = typer.Option(None, "--name", help="player name to sign the clear with (default: profile name)"),
    base_dir: Path = _BASE_DIR,
) -> None:
    """Publish a .quest recipe alongside a verified completion replay."""
    from grim.config import ensure_crimson_cfg

    from ..leaderboard.client import leaderboard_url, post_json
    from ..leaderboard.identity import Identity
    from ..quests.dsl import QuestCompileError, build_custom_quest
    from ..replay.codec import ReplayCodecError, encode_replay_payload, load_replay_file, zstd_pack
    from ..replay.ranked import outcome_reasons, unranked_reasons

    try:
        source = quest_file.read_text(encoding="utf-8")
        quest = build_custom_quest(source, seed=seed)
    except (OSError, QuestCompileError) as exc:
        typer.echo(f"quest compile failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    digest = quest.digest()
    chosen_replay = replay_file or _find_matching_clear_replay(base_dir / "replays", digest)
    if chosen_replay is None:
        typer.echo(
            f"no completed ranked replay found for '{quest.title}' (id {digest[:12]}).\n"
            f"beat it first with: uv run crimson --custom-quest {quest_file}",
            err=True,
        )
        raise typer.Exit(code=1)

    try:
        replay = load_replay_file(chosen_replay)
    except (OSError, ReplayCodecError) as exc:
        typer.echo(f"invalid replay {chosen_replay}: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if replay.run.custom_quest is None or replay.run.custom_quest.digest() != digest:
        typer.echo(f"replay {chosen_replay} does not match the compiled quest (expected id {digest[:12]})", err=True)
        raise typer.Exit(code=1)

    reasons = [*unranked_reasons(replay.run), *outcome_reasons(replay.run, replay.result)]
    if reasons:
        typer.echo(f"replay {chosen_replay} is not a completed ranked clear: {', '.join(reasons)}", err=True)
        raise typer.Exit(code=1)

    player_name = name
    if not player_name:
        try:
            cfg = ensure_crimson_cfg(base_dir)
            player_name = str(cfg.profile.player_name or "").strip()
        except (OSError, ValueError):
            player_name = ""
    player_name = player_name or quest.author or "Player"

    payload = encode_replay_payload(replay)
    packed = zstd_pack(payload)
    identity = Identity.load_or_create(base_dir)
    signature = identity.sign_run(payload, player_name)

    api = leaderboard_url()
    if not api:
        typer.echo("CRIMSON_LEADERBOARD_URL is empty; cannot publish.", err=True)
        raise typer.Exit(code=1)

    try:
        status, body = post_json(
            f"{api}/custom",
            {
                "replay": base64.b64encode(packed).decode("ascii"),
                "name": player_name,
                "public_key": identity.public_key.hex(),
                "signature": signature.hex(),
                "source": source,
                "seed": seed,
            },
        )
    except OSError as exc:
        typer.echo(f"could not reach {api}: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if status not in (200, 201):
        reason = body.get("reason") or f"HTTP {status}"
        typer.echo(f"publish refused: {reason}", err=True)
        raise typer.Exit(code=1)

    site = api.removesuffix("/api")
    url_path = body.get("url") or f"/custom/{digest[:12]}"
    typer.echo(f"published: {site}{url_path}")
