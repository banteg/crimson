from __future__ import annotations

import io
import inspect
import json
import random
import re
from pathlib import Path
from dataclasses import fields

import typer
from PIL import Image

from grim import jaz, paq
from grim.rand import Crand
from .paths import default_runtime_dir
from .creatures.spawn import SpawnEnv, build_spawn_plan, spawn_id_label
from .quests import all_quests
from .quests.types import QuestContext, QuestDefinition, SpawnEntry


app = typer.Typer(add_completion=False)

_QUEST_DEFS: dict[str, QuestDefinition] = {quest.level: quest for quest in all_quests()}
_QUEST_BUILDERS = {level: quest.builder for level, quest in _QUEST_DEFS.items()}
_QUEST_TITLES = {level: quest.title for level, quest in _QUEST_DEFS.items()}

_SEP_RE = re.compile(r"[\\/]+")


def _safe_relpath(name: str) -> Path:
    parts = [p for p in _SEP_RE.split(name) if p]
    if not parts:
        raise ValueError("empty entry name")
    for part in parts:
        if part in (".", ".."):
            raise ValueError(f"unsafe path part: {part!r}")
    return Path(*parts)


def _extract_one(paq_path: Path, assets_root: Path) -> int:
    out_root = assets_root / paq_path.stem
    out_root.mkdir(parents=True, exist_ok=True)
    count = 0
    for name, data in paq.iter_entries(paq_path):
        rel = _safe_relpath(name)
        dest = out_root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        suffix = dest.suffix.lower()
        if suffix == ".jaz":
            jaz_image = jaz.decode_jaz_bytes(data)
            base = dest.with_suffix("")
            jaz_image.composite_image().save(base.with_suffix(".png"))
        else:
            if suffix == ".tga":
                img = Image.open(io.BytesIO(data))
                img.save(dest.with_suffix(".png"))
            else:
                dest.write_bytes(data)
        count += 1
    return count


@app.command("extract")
def cmd_extract(game_dir: Path, assets_dir: Path) -> None:
    """Extract all .paq files into a flat asset directory."""
    if not game_dir.is_dir():
        typer.echo(f"game dir not found: {game_dir}", err=True)
        raise typer.Exit(code=1)
    assets_dir.mkdir(parents=True, exist_ok=True)
    paqs = sorted(game_dir.rglob("*.paq"))
    if not paqs:
        typer.echo(f"no .paq files under {game_dir}", err=True)
        raise typer.Exit(code=1)
    total = 0
    for paq_path in paqs:
        total += _extract_one(paq_path, assets_dir)
    typer.echo(f"extracted {total} files")


def _call_builder(builder, ctx: QuestContext, rng: random.Random | None) -> list[SpawnEntry]:
    params = inspect.signature(builder).parameters
    if "rng" in params:
        return builder(ctx, rng=rng)
    return builder(ctx)


def _format_entry(idx: int, entry: SpawnEntry, *, plan_info: tuple[int, int] | None) -> str:
    creature = spawn_id_label(entry.spawn_id)
    plan_text = ""
    if plan_info is not None:
        creatures_per_spawn, spawn_slots_per_spawn = plan_info
        alloc = entry.count * creatures_per_spawn
        plan_text = f"  alloc={alloc:3d} (x{creatures_per_spawn:2d})  slots={spawn_slots_per_spawn}"
    return (
        f"{idx:02d}  t={entry.trigger_ms:5d}  "
        f"id=0x{entry.spawn_id:02x} ({entry.spawn_id:2d})  "
        f"creature={creature:10s}  "
        f"count={entry.count:2d}  "
        f"x={entry.x:7.1f}  y={entry.y:7.1f}  heading={entry.heading:7.3f}{plan_text}"
    )


def _format_id(value: int | None) -> str:
    if value is None:
        return "none"
    return f"0x{value:02x} ({value})"


def _format_id_list(values: tuple[int, ...] | None) -> str:
    if not values:
        return "none"
    return "[" + ", ".join(_format_id(value) for value in values) + "]"


def _format_meta(quest: QuestDefinition) -> list[str]:
    builder_addr = f"0x{quest.builder_address:08x}" if quest.builder_address is not None else "unknown"
    terrain_ids = _format_id_list(quest.terrain_ids)
    return [
        f"time_limit_ms={quest.time_limit_ms}",
        f"start_weapon_id={quest.start_weapon_id}",
        f"unlock_perk_id={_format_id(quest.unlock_perk_id)}",
        f"unlock_weapon_id={_format_id(quest.unlock_weapon_id)}",
        f"builder_address={builder_addr}",
        f"terrain_ids={terrain_ids}",
    ]


@app.command("quests")
def cmd_quests(
    level: str = typer.Argument(..., help="quest level, e.g. 1.1"),
    width: int = typer.Option(1024, help="terrain width"),
    height: int = typer.Option(1024, help="terrain height"),
    player_count: int = typer.Option(1, help="player count"),
    seed: int | None = typer.Option(None, help="seed for randomized quests"),
    sort: bool = typer.Option(False, help="sort output by trigger time"),
    show_plan: bool = typer.Option(False, help="include spawn-plan allocation summary"),
) -> None:
    """Print quest spawn scripts for a given level."""
    quest = _QUEST_DEFS.get(level)
    if quest is None:
        available = ", ".join(sorted(_QUEST_BUILDERS))
        typer.echo(f"unknown level {level!r}. Available: {available}", err=True)
        raise typer.Exit(code=1)
    builder = quest.builder
    title = quest.title
    ctx = QuestContext(width=width, height=height, player_count=player_count)
    rng = random.Random(seed) if seed is not None else random.Random()
    entries = _call_builder(builder, ctx, rng)
    if sort:
        entries = sorted(entries, key=lambda e: (e.trigger_ms, e.spawn_id, e.x, e.y))
    typer.echo(f"Quest {level} {title} ({len(entries)} entries)")
    typer.echo("Meta: " + "; ".join(_format_meta(quest)))

    plan_cache: dict[int, tuple[int, int]] = {}
    if show_plan:
        env = SpawnEnv(
            terrain_width=float(width),
            terrain_height=float(height),
            demo_mode_active=True,
            hardcore=False,
            difficulty_level=0,
        )
        for entry in entries:
            if entry.spawn_id in plan_cache:
                continue
            plan = build_spawn_plan(entry.spawn_id, (512.0, 512.0), 0.0, Crand(0), env)
            plan_cache[entry.spawn_id] = (len(plan.creatures), len(plan.spawn_slots))
        total_alloc = sum(entry.count * plan_cache[entry.spawn_id][0] for entry in entries)
        total_slots = sum(entry.count * plan_cache[entry.spawn_id][1] for entry in entries)
        typer.echo(f"Plan: total_alloc={total_alloc} total_spawn_slots={total_slots}")

    for idx, entry in enumerate(entries, start=1):
        typer.echo(_format_entry(idx, entry, plan_info=plan_cache.get(entry.spawn_id)))


@app.command("view")
def cmd_view(
    name: str = typer.Argument(..., help="view name (e.g. empty)"),
    width: int = typer.Option(1024, help="window width"),
    height: int = typer.Option(768, help="window height"),
    fps: int = typer.Option(60, help="target fps"),
    preserve_bugs: bool = typer.Option(False, "--preserve-bugs", help="preserve known original exe bugs/quirks"),
    assets_dir: Path = typer.Option(Path("artifacts") / "assets", help="assets root (default: ./artifacts/assets)"),
) -> None:
    """Launch a Raylib debug view."""
    from grim.app import run_view
    from grim.view import ViewContext
    from .views import all_views, view_by_name

    view_def = view_by_name(name)
    if view_def is None:
        available = ", ".join(view.name for view in all_views())
        typer.echo(f"unknown view {name!r}. Available: {available}", err=True)
        raise typer.Exit(code=1)
    ctx = ViewContext(assets_dir=assets_dir, preserve_bugs=bool(preserve_bugs))
    params = inspect.signature(view_def.factory).parameters
    if "ctx" in params:
        view = view_def.factory(ctx=ctx)
    else:
        view = view_def.factory()
    title = f"{view_def.title} — Crimsonland"
    run_view(view, width=width, height=height, title=title, fps=fps)


@app.callback(invoke_without_command=True)
def cmd_game(
    ctx: typer.Context,
    width: int | None = typer.Option(None, help="window width (default: use crimson.cfg)"),
    height: int | None = typer.Option(None, help="window height (default: use crimson.cfg)"),
    fps: int = typer.Option(60, help="target fps"),
    seed: int | None = typer.Option(None, help="rng seed"),
    demo: bool = typer.Option(False, "--demo", help="enable shareware demo mode"),
    no_intro: bool = typer.Option(False, "--no-intro", help="skip company splashes and intro music"),
    debug: bool = typer.Option(False, "--debug", help="enable debug cheats and overlays"),
    preserve_bugs: bool = typer.Option(False, "--preserve-bugs", help="preserve known original exe bugs/quirks"),
    base_dir: Path = typer.Option(
        default_runtime_dir(),
        "--base-dir",
        "--runtime-dir",
        help="base path for runtime files (default: per-user OS data dir; override with CRIMSON_RUNTIME_DIR)",
    ),
    assets_dir: Path | None = typer.Option(
        None,
        help="assets root (default: base-dir; missing .paq files are downloaded)",
    ),
) -> None:
    """Run the reimplementation game flow (default command)."""
    if ctx.invoked_subcommand:
        return
    from .game import GameConfig, run_game

    config = GameConfig(
        base_dir=base_dir,
        assets_dir=assets_dir,
        width=width,
        height=height,
        fps=fps,
        seed=seed,
        demo_enabled=demo,
        no_intro=no_intro,
        debug=debug,
        preserve_bugs=bool(preserve_bugs),
    )
    run_game(config)


@app.command("config")
def cmd_config(
    path: Path | None = typer.Option(None, help="path to crimson.cfg (default: base-dir/crimson.cfg)"),
    base_dir: Path = typer.Option(
        default_runtime_dir(),
        "--base-dir",
        "--runtime-dir",
        help="base path for runtime files (default: per-user OS data dir; override with CRIMSON_RUNTIME_DIR)",
    ),
) -> None:
    """Inspect crimson.cfg configuration values."""
    from grim.config import CRIMSON_CFG_NAME, CRIMSON_CFG_STRUCT, load_crimson_cfg

    cfg_path = path if path is not None else base_dir / CRIMSON_CFG_NAME
    config = load_crimson_cfg(cfg_path)
    typer.echo(f"path: {config.path}")
    typer.echo(f"screen: {config.screen_width}x{config.screen_height}")
    typer.echo(f"windowed: {config.windowed_flag}")
    typer.echo(f"bpp: {config.screen_bpp}")
    typer.echo(f"texture_scale: {config.texture_scale}")
    typer.echo("fields:")
    for sub in CRIMSON_CFG_STRUCT.subcons:
        name = sub.name
        if not name:
            continue
        value = config.data[name]
        typer.echo(f"{name}: {_format_cfg_value(value)}")


def _format_cfg_value(value: object) -> str:
    if isinstance(value, (bytes, bytearray)):
        length = len(value)
        prefix = value.split(b"\x00", 1)[0]
        if prefix and all(32 <= b < 127 for b in prefix):
            text = prefix.decode("ascii", errors="replace")
            return f"{text!r} (len={length})"
        return f"0x{bytes(value).hex()} (len={length})"
    return str(value)


def _parse_int_auto(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError as exc:
        raise typer.BadParameter(f"invalid integer: {text!r}") from exc


def _dc_to_dict(obj: object) -> dict[str, object]:
    return {f.name: getattr(obj, f.name) for f in fields(obj)}


@app.command("spawn-plan")
def cmd_spawn_plan(
    template: str = typer.Argument(..., help="spawn id (e.g. 0x12)"),
    seed: str = typer.Option("0xBEEF", help="MSVCRT rand() seed (e.g. 0xBEEF)"),
    x: float = typer.Option(512.0, help="spawn x"),
    y: float = typer.Option(512.0, help="spawn y"),
    heading: float = typer.Option(0.0, help="heading (radians)"),
    terrain_w: float = typer.Option(1024.0, help="terrain width"),
    terrain_h: float = typer.Option(1024.0, help="terrain height"),
    demo_mode_active: bool = typer.Option(True, help="when true, burst effect is skipped"),
    hardcore: bool = typer.Option(False, help="hardcore mode"),
    difficulty: int = typer.Option(0, help="difficulty level"),
    as_json: bool = typer.Option(False, "--json", help="print JSON"),
) -> None:
    """Build and print a spawn plan for a single template id."""
    template_id = _parse_int_auto(template)
    rng = Crand(_parse_int_auto(seed))
    env = SpawnEnv(
        terrain_width=terrain_w,
        terrain_height=terrain_h,
        demo_mode_active=demo_mode_active,
        hardcore=hardcore,
        difficulty_level=difficulty,
    )
    plan = build_spawn_plan(template_id, (x, y), heading, rng, env)
    if as_json:
        payload: dict[str, object] = {
            "template_id": template_id,
            "pos": [x, y],
            "heading": heading,
            "seed": _parse_int_auto(seed),
            "env": {
                "terrain_width": terrain_w,
                "terrain_height": terrain_h,
                "demo_mode_active": demo_mode_active,
                "hardcore": hardcore,
                "difficulty_level": difficulty,
            },
            "primary": plan.primary,
            "creatures": [_dc_to_dict(c) for c in plan.creatures],
            "spawn_slots": [_dc_to_dict(s) for s in plan.spawn_slots],
            "effects": [_dc_to_dict(e) for e in plan.effects],
            "rng_state": rng.state,
        }
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    typer.echo(f"template_id=0x{template_id:02x} ({template_id}) creature={spawn_id_label(template_id)}")
    typer.echo(f"pos=({x:.1f},{y:.1f}) heading={heading:.6f} seed=0x{_parse_int_auto(seed):08x} rng_state=0x{rng.state:08x}")
    typer.echo(
        "env="
        f"demo_mode_active={demo_mode_active} "
        f"hardcore={hardcore} "
        f"difficulty={difficulty} "
        f"terrain={terrain_w:.0f}x{terrain_h:.0f}"
    )
    typer.echo(f"primary={plan.primary} creatures={len(plan.creatures)} slots={len(plan.spawn_slots)} effects={len(plan.effects)}")
    typer.echo("")
    typer.echo("creatures:")
    for idx, c in enumerate(plan.creatures):
        primary = "*" if idx == plan.primary else " "
        typer.echo(
            f"{primary}{idx:02d} type={c.type_id!s:14s} ai={c.ai_mode:2d} flags=0x{int(c.flags):03x} "
            f"pos=({c.pos_x:7.1f},{c.pos_y:7.1f}) health={c.health!s:>6s} size={c.size!s:>6s} link={c.ai_link_parent!s:>3s} "
            f"slot={c.spawn_slot!s:>3s}"
        )
    if plan.spawn_slots:
        typer.echo("")
        typer.echo("spawn_slots:")
        for idx, slot in enumerate(plan.spawn_slots):
            typer.echo(
                f"{idx:02d} owner={slot.owner_creature:02d} timer={slot.timer:.2f} count={slot.count:3d} "
                f"limit={slot.limit:3d} interval={slot.interval:.3f} child=0x{slot.child_template_id:02x}"
            )
    if plan.effects:
        typer.echo("")
        typer.echo("effects:")
        for fx in plan.effects:
            typer.echo(f"burst x={fx.x:.1f} y={fx.y:.1f} count={fx.count}")


@app.command("oracle")
def cmd_oracle(
    seed: int = typer.Option(0xBEEF, help="RNG seed for deterministic runs"),
    input_file: Path | None = typer.Option(None, "--input-file", "-i", help="JSON file with input sequence"),
    max_frames: int = typer.Option(36000, help="Maximum frames to run (default: 10 min at 60fps)"),
    frame_rate: int = typer.Option(60, help="Frame rate for simulation"),
    sample_rate: int = typer.Option(60, "--sample-rate", "-s", help="Emit state every N frames (1=every frame, 60=1/sec)"),
    preserve_bugs: bool = typer.Option(False, "--preserve-bugs", help="preserve known original exe bugs/quirks"),
    output_mode: str = typer.Option(
        "summary",
        "--output", "-o",
        help="Output mode: full (all entities), summary (fast), hash (ultra-fast), checkpoints (on events only)",
    ),
) -> None:
    """Run headless oracle mode for differential testing.

    Emits JSON game state to stdout. Use with --seed for deterministic runs
    and --input-file for replaying specific input sequences.

    Output modes:
      - summary: Score, kills, player pos/health (default, fast)
      - full: All entities including creatures, projectiles, bonuses
      - hash: SHA256 hash of full state (ultra-fast comparison)
      - checkpoints: Emit only when score/kills/level/weapon changes

    Examples:
        # Fast validation at 1 Hz sampling
        crimson oracle --seed 12345 -i replay.json -s 60 -o summary

        # Full frame-by-frame for debugging divergence
        crimson oracle --seed 12345 -i replay.json -s 1 -o full

        # Ultra-fast hash comparison
        crimson oracle --seed 12345 -i replay.json -o hash

        # Event-driven checkpoints only
        crimson oracle --seed 12345 -i replay.json -o checkpoints
    """
    from .oracle import OracleConfig, OutputMode, run_headless

    # Validate output mode
    mode_map = {
        "full": OutputMode.FULL,
        "summary": OutputMode.SUMMARY,
        "hash": OutputMode.HASH,
        "checkpoints": OutputMode.CHECKPOINTS,
    }
    if output_mode not in mode_map:
        typer.echo(f"Invalid output mode: {output_mode!r}. Choose from: {', '.join(mode_map)}", err=True)
        raise typer.Exit(code=1)

    config = OracleConfig(
        seed=seed,
        input_file=input_file,
        max_frames=max_frames,
        frame_rate=frame_rate,
        sample_rate=sample_rate,
        output_mode=mode_map[output_mode],
        preserve_bugs=bool(preserve_bugs),
    )
    run_headless(config)


@app.command("replay")
def cmd_replay(
    demo_path: Path = typer.Argument(..., help="path to a .crdemo file"),
    stop_on_game_over: bool = typer.Option(True, help="stop once all players are dead"),
    dump_fingerprints: bool = typer.Option(False, "--fingerprints", help="emit per-tick fingerprint JSONL"),
) -> None:
    """Replay a deterministic demo in headless mode and print the resulting score record."""
    import json

    from .game_modes import GameMode
    from .gameplay import perk_selection_current_choices, perk_selection_pick_by_id
    from .modes.components.highscore_record_builder import build_highscore_record_for_game_over
    from .perks import PerkId
    from .replay.crdemo import (
        ActionType,
        FLAG_AUTO_PICK_PERKS,
        FLAG_DEMO_MODE_ACTIVE,
        FLAG_HARDCORE,
        FLAG_PERK_PROGRESSION,
        FLAG_PRESERVE_BUGS,
        DemoError,
        load,
        iter_actions_by_tick,
    )
    from .sim.fingerprint import fingerprint_world_state
    from .sim.session import SurvivalSession

    demo = load(demo_path)
    header = demo.header
    if int(header.game_mode) != int(GameMode.SURVIVAL):
        raise typer.BadParameter("only Survival demos are supported right now")

    actions_by_tick = iter_actions_by_tick(demo.actions)

    status_blob = header.status_blob if header.status_blob else None
    session = SurvivalSession.build(
        world_size=float(header.world_size),
        player_count=int(header.player_count),
        player_inits=[(p.pos_x, p.pos_y, p.weapon_id) for p in header.player_inits],
        rng_state=int(header.rng_state),
        status_blob=status_blob,
        demo_mode_active=header.flag(FLAG_DEMO_MODE_ACTIVE),
        hardcore=header.flag(FLAG_HARDCORE),
        difficulty_level=int(header.difficulty_level),
        preserve_bugs=header.flag(FLAG_PRESERVE_BUGS),
        detail_preset=int(header.detail_preset),
        fx_toggle=int(header.fx_toggle),
        auto_pick_perks=header.flag(FLAG_AUTO_PICK_PERKS),
        perk_progression_enabled=header.flag(FLAG_PERK_PROGRESSION),
    )

    for tick, frame in enumerate(demo.frames):
        for action in actions_by_tick.get(int(tick), []):
            action_type = int(action.action_type)
            if action_type == int(ActionType.PERK_MENU_OPEN):
                perk_selection_current_choices(
                    session.world.state,
                    session.world.players,
                    session.world.state.perk_selection,
                    game_mode=int(GameMode.SURVIVAL),
                    player_count=len(session.world.players),
                )
                continue
            if action_type != int(ActionType.PERK_PICK):
                raise DemoError(f"unsupported action type: {action.action_type}")
            if not (0 <= int(action.player_index) < len(session.world.players)):
                raise DemoError(f"invalid player index: {action.player_index}")
            perk = PerkId(int(action.payload_u16))
            picked = perk_selection_pick_by_id(
                session.world.state,
                session.world.players,
                session.world.state.perk_selection,
                perk,
                game_mode=int(GameMode.SURVIVAL),
                player_count=len(session.world.players),
                dt=float(action.payload_f32),
                creatures=session.world.creatures.entries,
            )
            if picked is None:
                raise DemoError(f"perk pick failed at tick {tick}: {perk!s}")

        session.step(float(frame.dt), inputs=list(frame.inputs))

        if dump_fingerprints:
            fp = fingerprint_world_state(session.world)
            payload = {
                "tick": int(tick),
                "fingerprint": f"0x{fp:016x}",
                "rng_state": f"0x{int(session.world.state.rng.state):08x}",
                "score_xp": int(session.world.players[0].experience) if session.world.players else 0,
                "kills": int(session.world.creatures.kill_count),
            }
            print(json.dumps(payload, sort_keys=True), flush=True)

        if stop_on_game_over and session.is_game_over():
            break

    if not session.world.players:
        raise DemoError("demo ended with no players")

    record = build_highscore_record_for_game_over(
        state=session.world.state,
        player=session.world.players[0],
        survival_elapsed_ms=int(session.state.elapsed_ms),
        creature_kill_count=int(session.world.creatures.kill_count),
        game_mode_id=int(GameMode.SURVIVAL),
    )
    out = {
        "game_mode_id": int(record.game_mode_id),
        "score_xp": int(record.score_xp),
        "survival_elapsed_ms": int(record.survival_elapsed_ms),
        "creature_kill_count": int(record.creature_kill_count),
        "most_used_weapon_id": int(record.most_used_weapon_id),
        "shots_fired": int(record.shots_fired),
        "shots_hit": int(record.shots_hit),
    }
    typer.echo(json.dumps(out, sort_keys=True))


def main(argv: list[str] | None = None) -> None:
    app(prog_name="crimson", args=argv)


if __name__ == "__main__":
    main()
