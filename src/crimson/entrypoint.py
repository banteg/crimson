from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

DEFAULT_ASSETS_DIR = Path("artifacts") / "assets"
DEFAULT_BASE_DIR = Path("artifacts") / "runtime"


@dataclass(frozen=True, slots=True)
class BootStep:
    key: str
    title: str
    trace: str
    needs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EntrypointConfig:
    base_dir: Path = DEFAULT_BASE_DIR
    assets_dir: Path = DEFAULT_ASSETS_DIR


@dataclass(frozen=True, slots=True)
class EntrypointPlan:
    base_dir: Path
    assets_dir: Path
    steps: tuple[BootStep, ...]


BOOT_STEPS: tuple[BootStep, ...] = (
    BootStep(
        key="seed_dx",
        title="Seed RNG + DirectX presence check",
        trace="FUN_004623b2 + dx_get_version + Direct3DCreate8",
        needs=("rng", "dx_probe", "early_exit"),
    ),
    BootStep(
        key="paths_logging",
        title="Set base path + console banner/log flush",
        trace="crt_getcwd + console_flush_log",
        needs=("base_path", "console_log"),
    ),
    BootStep(
        key="config_cmds",
        title="Ensure config file + register console commands",
        trace="config_ensure_file + console_register_command",
        needs=("config_io", "console_cmds"),
    ),
    BootStep(
        key="grim_interface",
        title="Load Grim2D interface + register core cvars",
        trace="grim_load_interface + register_core_cvars",
        needs=("renderer_boot", "cvar_registry"),
    ),
    BootStep(
        key="config_save",
        title="Load presets + game status + sequence",
        trace="config_load_presets + game_load_status + game_sequence_load",
        needs=("config_presets", "save_io", "sequence_loader"),
    ),
    BootStep(
        key="apply_config",
        title="Apply Grim config + sync + read config vars",
        trace="grim_apply_config + config_sync_from_grim + grim_get_config_var",
        needs=("config_sync", "render_settings"),
    ),
    BootStep(
        key="init_system",
        title="Init input/render system + smallFnt.dat",
        trace="grim_init_system",
        needs=("input_init", "render_init", "small_font"),
    ),
    BootStep(
        key="post_init",
        title="Exec autoexec + register v_width/v_height + init audio/terrain",
        trace="console_exec_line + init_audio_and_terrain",
        needs=("console_exec", "cvars_screen", "audio_init", "terrain_init"),
    ),
    BootStep(
        key="logo_assets",
        title="Load logo/splash textures",
        trace=(
            "texture_get_or_load: backplasma, mockup, logo_esrb, "
            "loading, cl_logo"
        ),
        needs=("asset_loader", "jaz_tga_decoder", "texture_cache"),
    ),
    BootStep(
        key="render_logos",
        title="Render first company logo frame",
        trace="ui_render_* + draw textured quads",
        needs=("splash_scene", "sprite_draw"),
    ),
)


def build_entrypoint_plan(config: EntrypointConfig) -> EntrypointPlan:
    return EntrypointPlan(
        base_dir=config.base_dir,
        assets_dir=config.assets_dir,
        steps=BOOT_STEPS,
    )


def run_entrypoint(config: EntrypointConfig) -> EntrypointPlan:
    base_dir = config.base_dir
    base_dir.mkdir(parents=True, exist_ok=True)
    return build_entrypoint_plan(config)


def format_entrypoint_plan(plan: EntrypointPlan) -> str:
    lines = [
        f"Base path: {plan.base_dir}",
        f"Assets dir: {plan.assets_dir}",
        "",
        "Boot plan:",
    ]
    for idx, step in enumerate(plan.steps, start=1):
        needs = ", ".join(step.needs) if step.needs else "none"
        lines.append(f"{idx:02d}. {step.title}")
        lines.append(f"    trace: {step.trace}")
        lines.append(f"    needs: {needs}")
    return "\n".join(lines)
