from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from crimson import match as matchlib
from crimson import native_link
from crimson.library_match import match_coff_archive

REPO_ROOT = Path(__file__).resolve().parents[1]
PROVENANCE_PATH = REPO_ROOT / "analysis/library_provenance.json"
MATCH_ROOT = REPO_ROOT / "tools/match"


@dataclass(frozen=True, slots=True)
class RecoveredProviderRecipe:
    image: str
    derived_id: str
    output: Path
    scratches: tuple[str, ...]
    supplemental_scratches: tuple[Path, ...] = ()
    external_data_symbols: frozenset[str] = frozenset()


RECIPES = {
    "crimsonland.exe": RecoveredProviderRecipe(
        image="crimsonland.exe",
        derived_id="crimsonland-recovered-platform-vc6-provider",
        output=Path("crimsonland-platform/crimsonland-platform.lib"),
        scratches=(
            "dx_get_version",
            "dx_get_version_from_dxdiag",
            "dx_get_version_fallback_from_files",
            "win32_file_get_version_words",
            "dx_version_pack_4x16",
            "dx_version_compare_4x16",
            "reg_read_dword_default",
            "reg_write_dword",
        ),
    ),
    "grim.dll": RecoveredProviderRecipe(
        image="grim.dll",
        derived_id="grim-recovered-platform-vc6-provider",
        output=Path("grim-platform/grim-platform.lib"),
        scratches=(
            "grim_apply_config",
            "grim_app_cleanup",
            "grim_app_init",
            "grim_app_pump",
            "grim_app_shutdown",
            "grim_app_tick",
            "grim_d3d_init",
            "grim_d3d_shutdown",
            "grim_create_geometry_buffers",
            "grim_joystick_configure_axis",
            "grim_joystick_button_down",
            "grim_joystick_enum_device",
            "grim_joystick_init",
            "grim_joystick_poll",
            "grim_joystick_shutdown",
            "grim_keyboard_init",
            "grim_keyboard_key_down",
            "grim_keyboard_poll",
            "grim_keyboard_shutdown",
            "grim_mouse_button_down",
            "grim_mouse_init",
            "grim_mouse_poll",
            "grim_mouse_shutdown",
            "grim_release_geometry_buffers",
            "grim_restore_device_after_activation",
            "grim_restore_textures",
            "grim_save_screenshot",
            "grim_save_texture",
            "grim_window_create",
            "grim_window_destroy",
            "grim_run_loop",
            "grim_try_reset_device",
        ),
        supplemental_scratches=(Path("tools/native/providers/sources/grim_app_on_tick"),),
        external_data_symbols=frozenset(
            {
                "_GUID_SysKeyboard",
                "_GUID_SysMouse",
                "_IID_IDirectInput8A",
                "_c_dfDIJoystick2",
                "_c_dfDIKeyboard",
                "_c_dfDIMouse2",
            },
        ),
    ),
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _derived_row(derived_id: str) -> dict[str, Any]:
    payload = json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))
    rows = payload.get("derived_artifacts")
    if not isinstance(rows, list):
        raise TypeError("derived_artifacts must be an array")
    matches = [row for row in rows if isinstance(row, dict) and row.get("id") == derived_id]
    if len(matches) != 1:
        raise ValueError(f"derived_artifacts must contain one {derived_id!r} row")
    return cast(dict[str, Any], matches[0])


def _verify_file(path: Path, row: dict[str, Any], derived_id: str) -> None:
    expected_size = int(row["size"])
    expected_sha256 = str(row["sha256"])
    actual_size = path.stat().st_size
    actual_sha256 = _sha256(path)
    if actual_size != expected_size or actual_sha256 != expected_sha256:
        raise ValueError(
            f"{derived_id} mismatch: size={actual_size}/{expected_size} sha256={actual_sha256}/{expected_sha256}",
        )


def _run(argv: list[str], *, cwd: Path) -> None:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        env=os.environ.copy(),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode:
        detail = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part.strip())
        raise RuntimeError(
            f"{' '.join(argv)} failed ({completed.returncode})\n{detail}",
        )


def _toolchain(
    derived: dict[str, Any],
    derived_id: str,
) -> tuple[Path, Path]:
    compiler_root = MATCH_ROOT / "compilers/msvc6.5"
    library_tool = compiler_root / "Bin/LIB.EXE"
    wibo = MATCH_ROOT / "bin/wibo"
    if not library_tool.is_file() or not wibo.is_file():
        raise FileNotFoundError("MSVC 6.5 LIB.EXE and wibo are required")
    tools = derived.get("tools")
    if not isinstance(tools, dict):
        raise TypeError(f"{derived_id}: tools must be an object")
    for name, path in (("lib", library_tool), ("wibo", wibo)):
        expected = tools.get(f"{name}_sha256")
        actual = _sha256(path)
        if actual != expected:
            raise ValueError(
                f"{derived_id}: {name} sha256={actual}/{expected}",
            )
    return library_tool, wibo


def _compile_exact_scratch(
    recipe: RecoveredProviderRecipe,
    name: str,
    config: matchlib.ScratchConfig,
) -> Path:
    if config.image != recipe.image:
        raise ValueError(
            f"{name}: targets {config.image!r}, expected {recipe.image!r}",
        )
    object_path = matchlib.compile_scratch(config, MATCH_ROOT, force=True)
    result = matchlib.run_match(
        obj_path=object_path,
        function=config.function,
        image_path=matchlib.default_image_path(recipe.image),
        functions_path=matchlib.default_functions_path(recipe.image),
        metadata_path=matchlib.default_metadata_path(recipe.image),
        symbol_name=config.symbol,
        end_va=config.end_va,
        reference_aliases=config.reference_aliases,
        scope="all",
    )
    if not result.exact:
        raise ValueError(
            f"{name}: recovered provider is not exact "
            f"({result.ratio:.6%}, references="
            f"{result.masked_operand_audit.ok_count}/"
            f"{result.masked_operand_audit.unresolved_count}/"
            f"{result.masked_operand_audit.mismatch_count})",
        )
    return object_path


def _build_provider_data_object(
    recipe: RecoveredProviderRecipe,
    object_paths: dict[str, Path],
    temporary: Path,
) -> Path | None:
    primary_data_path = native_link.default_native_data_object_path(recipe.image)
    if not primary_data_path.is_file():
        raise FileNotFoundError(
            f"{primary_data_path}: run the native audit before building providers",
        )
    primary_data = matchlib.parse_coff_object(primary_data_path.read_bytes())
    primary_definitions = {
        symbol.name
        for symbol in primary_data.symbols
        if symbol.storage_class == matchlib.IMAGE_SYM_CLASS_EXTERNAL and symbol.section_number > 0
    }

    catalog = native_link.load_native_symbol_catalog(recipe.image, scope="all")
    referenced_by_symbol: dict[str, set[str]] = {}
    catalog_by_symbol: dict[str, tuple[dict[str, Any], ...]] = {}
    lookup_by_symbol: dict[str, str] = {}
    for name, object_path in object_paths.items():
        coff = matchlib.parse_coff_object(object_path.read_bytes())
        for symbol in coff.symbols:
            if (
                symbol.storage_class != matchlib.IMAGE_SYM_CLASS_EXTERNAL
                or symbol.section_number != 0
                or symbol.value != 0
                or symbol.name in primary_definitions
                or symbol.name in recipe.external_data_symbols
            ):
                continue
            lookup_name = matchlib._symbol_lookup_name(symbol.name)
            candidates = catalog.data.get(lookup_name, ())
            if not candidates:
                continue
            referenced_by_symbol.setdefault(symbol.name, set()).add(
                f"{name}.obj",
            )
            catalog_by_symbol[symbol.name] = candidates
            lookup_by_symbol[symbol.name] = lookup_name

    if not referenced_by_symbol:
        return None
    symbol_closure = {
        "unresolved": [
            {
                "catalog": list(catalog_by_symbol[symbol]),
                "category": "game_data",
                "lookup_name": lookup_by_symbol[symbol],
                "name": symbol,
                "referenced_by": [{"object": object_name} for object_name in sorted(referenced_by_symbol[symbol])],
            }
            for symbol in sorted(referenced_by_symbol)
        ],
    }
    output = temporary / f"{Path(recipe.image).stem}_platform_data.obj"
    record = native_link.build_native_data_object(
        recipe.image,
        symbol_closure=symbol_closure,
        reference_image_path=matchlib.default_image_path(recipe.image),
        output_path=output,
    )
    if record is None:
        raise ValueError(
            f"{recipe.image}: provider data dependencies emitted no object",
        )
    defined = {
        symbol.name
        for symbol in record.coff.symbols
        if symbol.storage_class == matchlib.IMAGE_SYM_CLASS_EXTERNAL and symbol.section_number > 0
    }
    missing = set(referenced_by_symbol) - defined
    if missing:
        raise ValueError(
            f"{recipe.image}: provider data object misses {sorted(missing)}",
        )
    overlap = defined & primary_definitions
    if overlap:
        raise ValueError(
            f"{recipe.image}: provider data object overlaps primary definitions {sorted(overlap)}",
        )
    return output


def _require_archive_match(
    recipe: RecoveredProviderRecipe,
    archive: Path,
    name: str,
    object_path: Path,
    config: matchlib.ScratchConfig,
) -> None:
    manifest = matchlib.load_function_manifest(
        matchlib.default_functions_path(recipe.image),
        metadata_path=matchlib.default_metadata_path(recipe.image),
        image_name=recipe.image,
        scope="all",
    )
    function = manifest.by_name[config.function]
    expected_symbol = matchlib.extract_object_function(
        matchlib.parse_coff_object(object_path.read_bytes()),
        config.symbol,
    ).name
    report = match_coff_archive(
        archive,
        image_path=matchlib.default_image_path(recipe.image),
        functions_path=matchlib.default_functions_path(recipe.image),
        metadata_path=matchlib.default_metadata_path(recipe.image),
        range_start=function.address,
        range_end=function.address + 1,
    )
    candidates = [
        candidate
        for match in report.matches
        if match.address == function.address
        for candidate in match.candidates
        if candidate.symbol == expected_symbol and candidate.member == f"{name}.obj"
    ]
    if len(candidates) != 1:
        raise ValueError(
            f"{archive.name}: no unique {name} match at 0x{function.address:08x}",
        )


def build_recovered_provider(
    recipe: RecoveredProviderRecipe,
    output_root: Path,
) -> Path:
    derived = _derived_row(recipe.derived_id)
    library_tool, wibo = _toolchain(derived, recipe.derived_id)
    with tempfile.TemporaryDirectory(
        prefix="crimson-recovered-providers-",
    ) as raw_temp:
        temporary = Path(raw_temp)
        object_names: list[str] = []
        object_paths: dict[str, Path] = {}
        configs = {name: matchlib.load_scratch_config(MATCH_ROOT / "scratches" / name) for name in recipe.scratches}
        for relative_directory in recipe.supplemental_scratches:
            directory = REPO_ROOT / relative_directory
            name = directory.name
            if name in configs:
                raise ValueError(f"{recipe.image}: duplicate provider object {name!r}")
            configs[name] = matchlib.load_scratch_config(directory)
        for name, config in configs.items():
            source = _compile_exact_scratch(recipe, name, config)
            destination = temporary / f"{name}.obj"
            destination.write_bytes(source.read_bytes())
            object_names.append(destination.name)
            object_paths[name] = destination
        if data_object := _build_provider_data_object(
            recipe,
            object_paths,
            temporary,
        ):
            object_names.append(data_object.name)

        archive = temporary / recipe.output.name
        _run(
            [
                str(wibo),
                str(library_tool),
                "/nologo",
                f"/out:{archive.name}",
                *object_names,
            ],
            cwd=temporary,
        )
        archive.write_bytes(
            native_link.normalize_coff_archive_timestamps(
                archive.read_bytes(),
            ),
        )
        for name, config in configs.items():
            _require_archive_match(
                recipe,
                archive,
                name,
                object_paths[name],
                config,
            )
        _verify_file(archive, derived, recipe.derived_id)

        output = output_root / recipe.output
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary_output = output.with_suffix(f"{output.suffix}.tmp")
        shutil.copyfile(archive, temporary_output)
        temporary_output.replace(output)
    return output


def build_recovered_providers(
    output_root: Path,
    images: tuple[str, ...] | None = None,
) -> tuple[Path, ...]:
    selected = images or tuple(RECIPES)
    return tuple(build_recovered_provider(RECIPES[image], output_root) for image in selected)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=("Build byte-proven recovered platform-provider archives."),
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=REPO_ROOT / "tools/native/providers/build",
        help="provider build directory",
    )
    parser.add_argument(
        "--image",
        action="append",
        choices=tuple(RECIPES),
        help="provider image to build (repeatable; defaults to all)",
    )
    args = parser.parse_args()
    outputs = build_recovered_providers(
        args.output_root.resolve(),
        tuple(args.image) if args.image else None,
    )
    for output in outputs:
        try:
            label = output.relative_to(REPO_ROOT)
        except ValueError:
            label = output
        print(
            f"{label} size={output.stat().st_size} sha256={_sha256(output)}",
        )


if __name__ == "__main__":
    main()
