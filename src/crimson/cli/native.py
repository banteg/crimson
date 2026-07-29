from __future__ import annotations

from pathlib import Path
from typing import Literal

import typer

from .. import match as matchlib
from .. import native_link

native_app = typer.Typer(add_completion=False)


@native_app.command("audit")
def cmd_native_audit(
    image: Literal["crimsonland.exe", "grim.dll"] = typer.Option(
        "grim.dll",
        "--image",
        help="native image to compile and audit",
    ),
    scope: Literal["port", "all"] = typer.Option(
        matchlib.DEFAULT_MATCH_SCOPE,
        "--scope",
        help="matching ownership scope",
    ),
    match_root: Path = typer.Option(
        matchlib.DEFAULT_MATCH_ROOT,
        "--match-root",
        help="tools/match root",
    ),
    output_directory: Path | None = typer.Option(
        None,
        "--out-dir",
        help="artifact directory (default: analysis/native/<image>)",
    ),
    jobs: int = typer.Option(
        matchlib.DEFAULT_MATCH_JOBS,
        "--jobs",
        "-j",
        min=1,
        help="parallel scratch evaluation jobs",
    ),
    require_game_closure: bool = typer.Option(
        False,
        "--require-game-closure",
        help="fail unless all game function/data references and strong definitions close",
    ),
) -> None:
    """Compile canonical objects and emit deterministic linker-closure artifacts."""

    output = output_directory or native_link.DEFAULT_NATIVE_ANALYSIS_ROOT / image
    try:
        audit = native_link.build_native_audit(
            image,
            scope=scope,
            match_root=match_root,
            jobs=jobs,
        )
        artifacts = native_link.write_native_audit(audit, output)
    except Exception as exc:
        typer.echo(f"native audit failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    object_summary = audit.object_manifest
    closure_summary = audit.symbol_closure["summary"]
    data_summary = audit.data_manifest["summary"]
    typer.echo(f"image={image} scope={scope}")
    typer.echo(
        f"objects={object_summary['object_count']} "
        f"states={object_summary['states']} "
        f"abi={object_summary['abi_assertions']['status'] if object_summary['abi_assertions'] else 'not-configured'} "
        f"functions={object_summary.get('function_count', object_summary['object_count'])} "
        f"clusters={object_summary.get('translation_units', {}).get('cluster_count', 0)}",
    )
    typer.echo(
        f"closure resolved={closure_summary['resolved_symbols']} "
        f"unresolved={closure_summary['unresolved_symbols']} "
        f"hard_duplicates={closure_summary['hard_duplicate_symbols']} "
        f"function_closed={closure_summary['function_closure']} "
        f"game_owned_closed={closure_summary['game_owned_closure']} "
        f"all_references_closed={closure_summary['all_references_closed']} "
        f"categories={closure_summary['unresolved_by_category']}",
    )
    typer.echo(
        f"function_debt={closure_summary.get('game_function_debt', {})} "
        f"duplicate_sections={closure_summary.get('hard_duplicate_by_section', {})}",
    )
    typer.echo(
        f"data entries={data_summary['entry_count']} "
        f"typed={data_summary['typed_entries']} "
        f"explicit_sizes={data_summary['explicit_size_entries']} "
        f"explicit_alignments={data_summary['explicit_alignment_entries']} "
        f"explicit_initializers={data_summary['explicit_initializer_entries']} "
        f"fully_specified={data_summary.get('fully_specified_entries', 0)} "
        f"referenced={data_summary.get('referenced_entries', 0)} "
        f"reference_fan_in={data_summary.get('game_data_reference_count', 0)}",
    )
    typer.echo(f"object_manifest={artifacts.object_manifest}")
    typer.echo(f"object_list={artifacts.object_list}")
    typer.echo(f"export_definition={artifacts.export_definition}")
    typer.echo(f"symbol_closure={artifacts.symbol_closure}")
    typer.echo(f"data_manifest={artifacts.data_manifest}")

    if require_game_closure and not closure_summary["game_owned_closure"]:
        raise typer.Exit(code=1)


@native_app.command("verify")
def cmd_native_verify(
    image: list[str] | None = typer.Option(
        None,
        "--image",
        help="checked-in native image to verify (repeatable; default: both images)",
    ),
    scope: Literal["port", "all"] = typer.Option(
        matchlib.DEFAULT_MATCH_SCOPE,
        "--scope",
        help="expected matching ownership scope",
    ),
    analysis_root: Path = typer.Option(
        native_link.DEFAULT_NATIVE_ANALYSIS_ROOT,
        "--analysis-root",
        help="root containing checked-in native audit artifacts",
    ),
    require_game_closure: bool = typer.Option(
        False,
        "--require-game-closure",
        help="fail unless every selected image passes game-owned closure",
    ),
    allow_absent_toolchain: bool = typer.Option(
        False,
        "--allow-absent-toolchain",
        help=(
            "allow ignored VC6/Wibo files to be absent while still hashing every "
            "available and tracked input"
        ),
    ),
) -> None:
    """Verify checked-in native artifacts without rebuilding their COFF objects."""

    images = tuple(image or matchlib.TRACKED_IMAGE_NAMES)
    unsupported = sorted(set(images) - set(matchlib.TRACKED_IMAGE_NAMES))
    if unsupported:
        typer.echo(
            f"native verify failed: unsupported images: {', '.join(unsupported)}",
            err=True,
        )
        raise typer.Exit(code=2)
    if len(images) != len(set(images)):
        typer.echo("native verify failed: duplicate --image values", err=True)
        raise typer.Exit(code=2)

    statuses = matchlib.collect_native_link_statuses(
        analysis_root=analysis_root,
        scope=scope,
        images=images,
        allow_absent_toolchain=allow_absent_toolchain,
    )
    for status in statuses:
        typer.echo(
            f"image={status.image} artifacts={status.artifact_state} "
            f"function_closed={status.function_closure} "
            f"game_owned_closed={status.game_owned_closure} "
            f"all_references_closed={status.all_references_closed}",
        )
        typer.echo(f"artifact_note={status.artifact_note}")

    if any(status.artifact_state != "current" for status in statuses):
        raise typer.Exit(code=2)
    if require_game_closure and any(
        status.game_owned_closure is not True
        for status in statuses
    ):
        raise typer.Exit(code=1)


@native_app.command("link")
def cmd_native_link(
    image: Literal["crimsonland.exe", "grim.dll"] = typer.Option(
        "grim.dll",
        "--image",
        help="native image to structurally link",
    ),
    scope: Literal["port", "all"] = typer.Option(
        matchlib.DEFAULT_MATCH_SCOPE,
        "--scope",
        help="matching ownership scope",
    ),
    match_root: Path = typer.Option(
        matchlib.DEFAULT_MATCH_ROOT,
        "--match-root",
        help="tools/match root",
    ),
    output_directory: Path | None = typer.Option(
        None,
        "--out-dir",
        help="linked artifact directory (default: analysis/native/<image>/link)",
    ),
    provider_config: Path | None = typer.Option(
        None,
        "--provider-config",
        help="provider manifest (default: tools/native/providers/<image>.json)",
    ),
    jobs: int = typer.Option(
        matchlib.DEFAULT_MATCH_JOBS,
        "--jobs",
        "-j",
        min=1,
        help="parallel scratch evaluation jobs",
    ),
) -> None:
    """Build a provenance-backed structural PE from the canonical object set."""

    output = (
        output_directory
        or native_link.DEFAULT_NATIVE_ANALYSIS_ROOT / image / "link"
    )
    config_path = (
        provider_config
        or native_link.DEFAULT_PROVIDER_CONFIGS.get(image)
    )
    if config_path is None:
        typer.echo(f"native link failed: no provider config for {image}", err=True)
        raise typer.Exit(code=2)
    try:
        audit = native_link.build_native_audit(
            image,
            scope=scope,
            match_root=match_root,
            jobs=jobs,
        )
        native_link.write_native_audit(
            audit,
            native_link.DEFAULT_NATIVE_ANALYSIS_ROOT / image,
        )
        config = native_link.load_native_provider_config(
            config_path,
            image=image,
        )
        artifacts, manifest = native_link.link_native_image(
            audit,
            config,
            output,
        )
    except Exception as exc:
        typer.echo(f"native link failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    summary = manifest["summary"]
    retained_placeholders = summary.get("retained_placeholder_symbols")
    placeholder_summary = str(summary["placeholder_symbols"])
    if retained_placeholders is not None:
        placeholder_summary = (
            f"{retained_placeholders}/{summary['placeholder_symbols']}"
        )
    typer.echo(f"image={image} mode={manifest['mode']} status={manifest['status']}")
    typer.echo(
        f"providers={len(manifest['providers'])} "
        f"covered={summary['covered_symbols']} "
        f"imports={summary['import_symbols']} "
        f"exports={summary['import_exports']} "
        f"archives={summary['archive_symbols']} "
        f"generated_imports={summary['generated_import_symbols']} "
        f"link_deps={summary['link_dependency_symbols']} "
        f"placeholders={placeholder_summary} "
        f"runnable={manifest['runnable']}",
    )
    typer.echo(f"linked_image={artifacts.image}")
    typer.echo(f"link_manifest={artifacts.manifest}")
    typer.echo(f"link_log={artifacts.log}")
