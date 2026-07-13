from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import typer

from .. import match as matchlib

match_app = typer.Typer(add_completion=False)


def _parse_hex(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    return int(value, 0)


def _echo_result(result: matchlib.MatchResult) -> None:
    typer.echo(
        f"match={result.ratio:.2%} "
        f"prefix={result.prefix_instructions}/{len(result.target_lines)} "
        f"target_insns={len(result.target_lines)} "
        f"candidate_insns={len(result.candidate_lines)} "
        f"refs={result.masked_operand_audit.ok_count}/"
        f"{result.masked_operand_audit.unresolved_count}/"
        f"{result.masked_operand_audit.mismatch_count}",
    )
    if result.ratio != 1.0:
        typer.echo(f"first_target={result.first_target_mismatch}")
        typer.echo(f"first_candidate={result.first_candidate_mismatch}")


def _reference_text(references: tuple[matchlib.MaskedReference, ...]) -> str:
    return ", ".join(
        f"{reference.text} ({'|'.join(reference.keys) if reference.keys else '?'})" for reference in references
    )


def _reference_json(reference: matchlib.MaskedReference) -> dict[str, object]:
    return {
        "operand_index": reference.operand_index,
        "kind": reference.kind,
        "source": reference.source,
        "value": reference.value,
        "text": reference.text,
        "keys": list(reference.keys),
        "explained": reference.explained,
    }


def _echo_audit_entry(entry: matchlib.MaskedOperandAuditEntry, *, prefix: str = "") -> None:
    typer.echo(
        f"{prefix}{entry.status} target=0x{entry.target_address:08x} "
        f"candidate=+0x{entry.candidate_offset:x} {entry.instruction}",
    )
    typer.echo(f"{prefix}  target: {_reference_text(entry.target_references)}")
    typer.echo(f"{prefix}  candidate: {_reference_text(entry.candidate_references)}")


def _finish_diff(
    result: matchlib.MatchResult,
    *,
    full: bool,
    regions: bool,
    region_context: int,
) -> None:
    _echo_result(result)
    if regions and result.ratio != 1.0:
        for index, region in enumerate(matchlib.diff_regions(result, context=region_context), start=1):
            typer.echo(
                f"\nregion {index}: target={region.target_span} "
                f"candidate={region.candidate_span} match={region.ratio:.2%} "
                f"prefix={region.prefix_instructions}",
            )
            for line in region.target_lines:
                typer.echo(f"- {line}")
            for line in region.candidate_lines:
                typer.echo(f"+ {line}")
    if result.ratio != 1.0:
        for line in result.diff_lines(full=full):
            typer.echo(line)
        raise typer.Exit(code=1)
    if result.masked_operand_audit.problem_count:
        for entry in result.masked_operand_audit.entries:
            if entry.status != "ok":
                _echo_audit_entry(entry)
        raise typer.Exit(code=1)


@match_app.command("diff")
def cmd_match_diff(
    obj_path: Path = typer.Argument(..., help="candidate COFF .obj"),
    function: str = typer.Argument(..., help="manifest function name or start VA"),
    image: Path = typer.Option(matchlib.DEFAULT_IMAGE_PATH, "--image", help="target PE image"),
    functions: Path = typer.Option(matchlib.DEFAULT_FUNCTIONS_PATH, "--functions", help="IDA functions manifest"),
    metadata: Path = typer.Option(matchlib.DEFAULT_METADATA_PATH, "--metadata", help="IDA metadata manifest"),
    end: str | None = typer.Option(None, "--end", help="override target end VA"),
    symbol: str | None = typer.Option(None, "--symbol", help="candidate object function symbol filter"),
    full: bool = typer.Option(False, "--full", help="print the full normalized unified diff"),
    regions: bool = typer.Option(False, "--regions", help="print localized mismatch regions before the diff"),
    region_context: int = typer.Option(4, "--region-context", min=0, help="context for --regions"),
) -> None:
    """Diff a compiled scratch object against a native image function."""
    try:
        result = matchlib.run_match(
            obj_path=obj_path,
            function=function,
            image_path=image,
            functions_path=functions,
            metadata_path=metadata,
            symbol_name=symbol,
            end_va=_parse_hex(end),
        )
    except Exception as exc:
        typer.echo(f"match failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    _finish_diff(result, full=full, regions=regions, region_context=region_context)


@match_app.command("scratch")
def cmd_match_scratch(
    directory: Path = typer.Argument(..., help="scratch directory containing scratch.conf"),
    match_root: Path = typer.Option(matchlib.DEFAULT_MATCH_ROOT, "--match-root", help="tools/match root"),
    full: bool = typer.Option(False, "--full", help="print the full normalized unified diff"),
    regions: bool = typer.Option(False, "--regions", help="print localized mismatch regions before the diff"),
    region_context: int = typer.Option(4, "--region-context", min=0, help="context for --regions"),
) -> None:
    """Compile and compare one configured scratch through the cached pipeline."""
    try:
        config = matchlib.load_scratch_config(directory.resolve())
        obj_path = matchlib.compile_scratch(config, match_root)
        image_path = matchlib.default_image_path(config.image)
        result = matchlib.run_match(
            obj_path=obj_path,
            function=config.function,
            image_path=image_path,
            functions_path=matchlib.default_functions_path(config.image),
            metadata_path=matchlib.default_metadata_path(config.image),
            symbol_name=config.symbol,
            end_va=config.end_va,
        )
    except Exception as exc:
        typer.echo(f"match failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    _finish_diff(result, full=full, regions=regions, region_context=region_context)


@match_app.command("dump")
def cmd_match_dump(
    obj_path: Path = typer.Argument(..., help="candidate COFF .obj"),
    function: str = typer.Argument(..., help="manifest function name or start VA"),
    side: Literal["target", "candidate", "both"] = typer.Option("both", "--side", help="listing side to print"),
    image: Path = typer.Option(matchlib.DEFAULT_IMAGE_PATH, "--image", help="target PE image"),
    functions: Path = typer.Option(matchlib.DEFAULT_FUNCTIONS_PATH, "--functions", help="IDA functions manifest"),
    metadata: Path = typer.Option(matchlib.DEFAULT_METADATA_PATH, "--metadata", help="IDA metadata manifest"),
    end: str | None = typer.Option(None, "--end", help="override target end VA"),
    symbol: str | None = typer.Option(None, "--symbol", help="candidate object function symbol filter"),
    start_offset: int = typer.Option(0, "--start-offset", min=0, help="skip normalized instructions"),
    count: int | None = typer.Option(None, "--count", min=1, help="maximum normalized instructions to print"),
) -> None:
    """Dump normalized target/candidate assembly listings."""
    try:
        dump = matchlib.run_match_dump(
            obj_path=obj_path,
            function=function,
            image_path=image,
            functions_path=functions,
            metadata_path=metadata,
            symbol_name=symbol,
            end_va=_parse_hex(end),
        )
    except Exception as exc:
        typer.echo(f"dump failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    def emit(name: str, lines: tuple[matchlib.DisassemblyLine, ...]) -> None:
        typer.echo(f"{name}:")
        visible = lines[start_offset : None if count is None else start_offset + count]
        for line in visible:
            typer.echo(f"{line.offset:04x}  {line.address:08x}  {line.text}")

    if side in ("target", "both"):
        emit("target", dump.target_lines)
    if side == "both":
        typer.echo("")
    if side in ("candidate", "both"):
        emit("candidate", dump.candidate_lines)


@match_app.command("validate")
def cmd_match_validate(source: Path = typer.Argument(..., help="scratch source file")) -> None:
    """Reject fakematching-only scratch constructs."""
    try:
        matchlib.validate_scratch_source(source)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("ok")


@match_app.command("status")
def cmd_match_status(
    match_root: Path = typer.Option(matchlib.DEFAULT_MATCH_ROOT, "--match-root", help="tools/match root"),
    compiler: str | None = typer.Option(None, "--compiler", help="override scratch compiler for this status run"),
    cflags: str | None = typer.Option(None, "--cflags", help="override scratch compiler flags for this status run"),
    jobs: int = typer.Option(matchlib.DEFAULT_MATCH_JOBS, "--jobs", "-j", min=1, help="parallel scratch jobs"),
    write: Path | None = typer.Option(None, "--write", help="write markdown status to this path"),
    check: bool = typer.Option(False, "--check", help="fail if any scratch cannot be evaluated"),
) -> None:
    """Compile all scratches and print their current match scores."""
    statuses = matchlib.collect_scratch_statuses(match_root, compiler=compiler, cflags=cflags, jobs=jobs)
    totals = matchlib.collect_image_totals(statuses)
    typer.echo(matchlib.render_status_table(statuses, totals))
    if write is not None:
        write.parent.mkdir(parents=True, exist_ok=True)
        write.write_text(matchlib.render_status_markdown(statuses, totals), encoding="utf-8")
    if check and any(status.state == "error" for status in statuses):
        raise typer.Exit(code=1)


@match_app.command("audit")
def cmd_match_audit(
    match_root: Path = typer.Option(matchlib.DEFAULT_MATCH_ROOT, "--match-root", help="tools/match root"),
    compiler: str | None = typer.Option(None, "--compiler", help="override scratch compiler"),
    cflags: str | None = typer.Option(None, "--cflags", help="override scratch compiler flags"),
    jobs: int = typer.Option(matchlib.DEFAULT_MATCH_JOBS, "--jobs", "-j", min=1, help="parallel scratch jobs"),
    status: Literal["problem", "unresolved", "mismatch", "all"] = typer.Option(
        "problem",
        "--status",
        help="masked-reference entries to show",
    ),
    exact_only: bool = typer.Option(
        True,
        "--exact-only/--all-scores",
        help="restrict the report to 100% instruction matches",
    ),
    limit: int | None = typer.Option(None, "--limit", min=1, help="maximum entries to show"),
    as_json: bool = typer.Option(False, "--json", help="emit machine-readable JSON"),
) -> None:
    """Report what each normalized ADDR refers to on both sides."""
    statuses = matchlib.collect_scratch_statuses(match_root, compiler=compiler, cflags=cflags, jobs=jobs)
    rows: list[tuple[matchlib.ScratchStatus, matchlib.MaskedOperandAuditEntry]] = []
    for scratch in statuses:
        if exact_only and scratch.ratio != 1.0:
            continue
        for entry in scratch.audit.entries:
            if status == "problem" and entry.status == "ok":
                continue
            if status in ("unresolved", "mismatch") and entry.status != status:
                continue
            rows.append((scratch, entry))
    if limit is not None:
        rows = rows[:limit]

    if as_json:
        typer.echo(
            json.dumps(
                [
                    {
                        "image": scratch.config.image,
                        "function": scratch.config.function,
                        "status": entry.status,
                        "target_address": entry.target_address,
                        "candidate_offset": entry.candidate_offset,
                        "instruction": entry.instruction,
                        "target": [_reference_json(reference) for reference in entry.target_references],
                        "candidate": [_reference_json(reference) for reference in entry.candidate_references],
                    }
                    for scratch, entry in rows
                ],
                indent=2,
                sort_keys=True,
            ),
        )
    else:
        for scratch, entry in rows:
            _echo_audit_entry(entry, prefix=f"{scratch.config.image}:{scratch.config.function}: ")
        typer.echo(f"entries={len(rows)}")
