from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import typer

from .. import match as matchlib

match_app = typer.Typer(add_completion=False)


def _parse_hex(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    return int(value, 0)


def _parse_csv(value: str | None) -> set[str] | None:
    if value is None:
        return None
    parsed = {item.strip() for item in value.split(",") if item.strip()}
    return parsed or None


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
    max_regions: int | None,
    as_json: bool,
) -> None:
    if as_json:
        typer.echo(
            json.dumps(
                matchlib.match_result_payload(
                    result,
                    region_context=region_context,
                    max_regions=max_regions,
                ),
                indent=2,
                sort_keys=True,
            ),
        )
        if result.ratio != 1.0 or result.masked_operand_audit.problem_count:
            raise typer.Exit(code=1)
        return

    _echo_result(result)
    if regions and result.ratio != 1.0:
        for index, region in enumerate(
            matchlib.diff_regions(result, context=region_context, max_regions=max_regions),
            start=1,
        ):
            typer.echo(
                f"\nregion {index}: target={region.target_span} "
                f"candidate={region.candidate_span} match={region.ratio:.2%} "
                f"prefix={region.prefix_instructions} "
                f"target_bytes={region.target_byte_span} "
                f"target_va={region.target_address_span} "
                f"candidate_bytes={region.candidate_byte_span} "
                f"fuzzy={region.fuzzy_weighted_bytes:.0f}/{region.target_byte_count} "
                f"refs={region.masked_ok}/{region.masked_unresolved}/{region.masked_mismatches}",
            )
            typer.echo(f"  hints: {', '.join(region.hints)}")
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
    max_regions: int | None = typer.Option(None, "--max-regions", min=1, help="maximum mismatch regions"),
    as_json: bool = typer.Option(False, "--json", help="emit match and region data as JSON"),
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

    _finish_diff(
        result,
        full=full,
        regions=regions,
        region_context=region_context,
        max_regions=max_regions,
        as_json=as_json,
    )


@match_app.command("scratch")
def cmd_match_scratch(
    directory: Path = typer.Argument(..., help="scratch directory containing scratch.conf"),
    match_root: Path = typer.Option(matchlib.DEFAULT_MATCH_ROOT, "--match-root", help="tools/match root"),
    full: bool = typer.Option(False, "--full", help="print the full normalized unified diff"),
    regions: bool = typer.Option(False, "--regions", help="print localized mismatch regions before the diff"),
    region_context: int = typer.Option(4, "--region-context", min=0, help="context for --regions"),
    max_regions: int | None = typer.Option(None, "--max-regions", min=1, help="maximum mismatch regions"),
    as_json: bool = typer.Option(False, "--json", help="emit match and region data as JSON"),
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
            reference_aliases=config.reference_aliases,
        )
    except Exception as exc:
        typer.echo(f"match failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    _finish_diff(
        result,
        full=full,
        regions=regions,
        region_context=region_context,
        max_regions=max_regions,
        as_json=as_json,
    )


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


@match_app.command("probe")
def cmd_match_probe(
    directory: Path = typer.Argument(..., help="scratch directory containing scratch.conf"),
    source: Path | None = typer.Option(None, "--source", help="temporary replacement source"),
    use_stdin: bool = typer.Option(False, "--stdin", help="read temporary replacement source from stdin"),
    match_root: Path = typer.Option(matchlib.DEFAULT_MATCH_ROOT, "--match-root", help="tools/match root"),
    compiler: str | None = typer.Option(None, "--compiler", help="profile used for baseline and probe"),
    cflags: str | None = typer.Option(None, "--cflags", help="flags used for baseline and probe"),
    label: str | None = typer.Option(None, "--label", help="short experiment label"),
    record: bool = typer.Option(False, "--record", help="append the result to experiments.jsonl"),
    as_json: bool = typer.Option(False, "--json", help="emit machine-readable JSON"),
) -> None:
    """Compare an untracked source overlay against the current scratch."""
    if source is None and not use_stdin:
        raise typer.BadParameter("pass --source or --stdin")
    if source is not None and use_stdin:
        raise typer.BadParameter("--source and --stdin are mutually exclusive")
    try:
        config = matchlib.load_scratch_config(directory.resolve())
        if use_stdin:
            source_text = sys.stdin.read()
        else:
            assert source is not None
            source_text = source.read_text(encoding="utf-8")
        result = matchlib.evaluate_source_probe(
            config,
            source_text,
            match_root=match_root,
            compiler=compiler,
            cflags=cflags,
            label=label,
        )
    except Exception as exc:
        typer.echo(f"probe failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    payload = matchlib.probe_result_payload(result)
    if record:
        record_path = config.directory / "experiments.jsonl"
        record_payload = {
            "recorded_at": datetime.now(UTC).isoformat(),
            **payload,
        }
        with record_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record_payload, separators=(",", ":"), sort_keys=True) + "\n")
        payload["recorded_to"] = str(record_path)
    if as_json:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        typer.echo(matchlib.render_probe_result(result))
        if record:
            typer.echo(f"recorded={payload['recorded_to']}")
    if result.baseline.state == "error" or result.probe.state == "error":
        raise typer.Exit(code=2)


@match_app.command("profiles")
def cmd_match_profiles(
    directory: Path = typer.Argument(..., help="scratch directory containing scratch.conf"),
    match_root: Path = typer.Option(matchlib.DEFAULT_MATCH_ROOT, "--match-root", help="tools/match root"),
    compiler: list[str] | None = typer.Option(None, "--compiler", help="compiler to try; repeat for a matrix"),
    cflags: list[str] | None = typer.Option(None, "--cflags", help="flag set to try; repeat for a matrix"),
    as_json: bool = typer.Option(False, "--json", help="emit machine-readable JSON"),
    check: bool = typer.Option(False, "--check", help="fail when any requested profile cannot be evaluated"),
) -> None:
    """Rank a compiler/flags matrix for one scratch."""
    try:
        config = matchlib.load_scratch_config(directory.resolve())
        compilers = tuple(compiler or matchlib.available_scratch_compilers(match_root) or (config.compiler,))
        flag_sets = tuple(cflags or (config.cflags,))
        statuses = matchlib.evaluate_profile_matrix(
            config,
            compilers=compilers,
            cflags=flag_sets,
            match_root=match_root,
        )
    except Exception as exc:
        typer.echo(f"profile sweep failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    ranked = matchlib.sort_profile_statuses(statuses)
    if as_json:
        typer.echo(json.dumps([matchlib.scratch_status_payload(status) for status in ranked], indent=2, sort_keys=True))
    else:
        typer.echo(matchlib.render_profile_table(ranked))
    if check and any(status.state == "error" for status in statuses):
        raise typer.Exit(code=1)


@match_app.command("status")
def cmd_match_status(
    match_root: Path = typer.Option(matchlib.DEFAULT_MATCH_ROOT, "--match-root", help="tools/match root"),
    compiler: str | None = typer.Option(None, "--compiler", help="override scratch compiler for this status run"),
    cflags: str | None = typer.Option(None, "--cflags", help="override scratch compiler flags for this status run"),
    jobs: int = typer.Option(matchlib.DEFAULT_MATCH_JOBS, "--jobs", "-j", min=1, help="parallel scratch jobs"),
    write: Path | None = typer.Option(None, "--write", help="write markdown status to this path"),
    check: bool = typer.Option(False, "--check", help="fail if any scratch cannot be evaluated"),
    image: str | None = typer.Option(None, "--image", help="show rows for one image"),
    state: str | None = typer.Option(None, "--state", help="comma-separated row states"),
    min_bytes: int = typer.Option(0, "--min-bytes", min=0, help="minimum target bytes"),
    sort_by: Literal["address", "fuzzy-gap", "size", "match"] = typer.Option(
        "address",
        "--sort",
        help="row ordering",
    ),
    limit: int | None = typer.Option(None, "--limit", min=1, help="maximum rows to show"),
    summary_only: bool = typer.Option(False, "--summary-only", help="print totals without scratch rows"),
    as_json: bool = typer.Option(False, "--json", help="emit machine-readable JSON"),
) -> None:
    """Compile all scratches and print their current match scores."""
    statuses = matchlib.collect_scratch_statuses(match_root, compiler=compiler, cflags=cflags, jobs=jobs)
    totals = matchlib.collect_image_totals(statuses)
    selected_totals = [total for total in totals if image is None or total.image == image]
    selected_statuses = [
        status
        for status in statuses
        if (image is None or status.config.image == image) and status.target_size >= min_bytes
    ]
    states = _parse_csv(state)
    if states is not None:
        unknown_states = states - {"match", "audit", "wip", "error"}
        if unknown_states:
            raise typer.BadParameter(f"unknown states: {', '.join(sorted(unknown_states))}", param_hint="--state")
        selected_statuses = [status for status in selected_statuses if status.state in states]
    selected_statuses = matchlib.sort_scratch_statuses(selected_statuses, sort_by=sort_by)
    if limit is not None:
        selected_statuses = selected_statuses[:limit]

    if as_json:
        typer.echo(
            json.dumps(
                {
                    "totals": [matchlib.image_totals_payload(total) for total in selected_totals],
                    "statuses": (
                        []
                        if summary_only
                        else [matchlib.scratch_status_payload(status) for status in selected_statuses]
                    ),
                },
                indent=2,
                sort_keys=True,
            ),
        )
    elif summary_only:
        typer.echo(matchlib.render_status_summary(selected_totals))
    else:
        typer.echo(matchlib.render_status_table(selected_statuses, selected_totals, sort_by=sort_by))
    if write is not None:
        write.parent.mkdir(parents=True, exist_ok=True)
        write.write_text(matchlib.render_status_markdown(statuses, totals), encoding="utf-8")
    if check and any(status.state == "error" for status in statuses):
        raise typer.Exit(code=1)


@match_app.command("triage")
def cmd_match_triage(
    match_root: Path = typer.Option(matchlib.DEFAULT_MATCH_ROOT, "--match-root", help="tools/match root"),
    compiler: str | None = typer.Option(None, "--compiler", help="override scratch compiler"),
    cflags: str | None = typer.Option(None, "--cflags", help="override scratch compiler flags"),
    jobs: int = typer.Option(matchlib.DEFAULT_MATCH_JOBS, "--jobs", "-j", min=1, help="parallel scratch jobs"),
    image: str | None = typer.Option(None, "--image", help="restrict to one tracked image"),
    state: str | None = typer.Option(None, "--state", help="comma-separated manifest states"),
    min_bytes: int = typer.Option(0, "--min-bytes", min=0, help="minimum native function bytes"),
    sort_by: Literal["address", "fuzzy-gap", "size", "fuzzy"] = typer.Option(
        "fuzzy-gap",
        "--sort",
        help="row ordering",
    ),
    limit: int | None = typer.Option(None, "--limit", min=1, help="maximum rows to show"),
    summary_only: bool = typer.Option(False, "--summary-only", help="print aggregate coverage only"),
    as_json: bool = typer.Option(False, "--json", help="emit machine-readable JSON"),
    check: bool = typer.Option(False, "--check", help="fail if any scratch cannot be evaluated"),
) -> None:
    """Rank every native function by address-keyed recovery opportunity."""
    statuses = matchlib.collect_scratch_statuses(match_root, compiler=compiler, cflags=cflags, jobs=jobs)
    rows = matchlib.collect_triage_rows(statuses, images=(image,) if image is not None else None)
    states = _parse_csv(state)
    if states is not None:
        unknown_states = states - {"match", "audit", "wip", "error", "missing"}
        if unknown_states:
            raise typer.BadParameter(f"unknown states: {', '.join(sorted(unknown_states))}", param_hint="--state")
        rows = [row for row in rows if row.state in states]
    rows = [row for row in rows if row.target_size >= min_bytes]
    rows = matchlib.sort_triage_rows(rows, sort_by=sort_by)
    if limit is not None:
        rows = rows[:limit]

    if as_json:
        typer.echo(
            json.dumps(
                {
                    "summary": matchlib.triage_summary_payload(rows),
                    "rows": [] if summary_only else [matchlib.triage_row_payload(row) for row in rows],
                },
                indent=2,
                sort_keys=True,
            ),
        )
    elif summary_only:
        typer.echo(matchlib.render_triage_summary(rows))
    else:
        typer.echo(matchlib.render_triage_table(rows, sort_by=sort_by))
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
