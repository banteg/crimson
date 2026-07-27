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
        f"abi={object_summary['abi_assertions']['status'] if object_summary['abi_assertions'] else 'not-configured'}",
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
        f"explicit_initializers={data_summary['explicit_initializer_entries']}",
    )
    typer.echo(f"object_manifest={artifacts.object_manifest}")
    typer.echo(f"object_list={artifacts.object_list}")
    typer.echo(f"export_definition={artifacts.export_definition}")
    typer.echo(f"symbol_closure={artifacts.symbol_closure}")
    typer.echo(f"data_manifest={artifacts.data_manifest}")

    if require_game_closure and not closure_summary["game_owned_closure"]:
        raise typer.Exit(code=1)
