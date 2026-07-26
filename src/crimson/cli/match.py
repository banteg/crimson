from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import typer

from .. import library_provenance as provenance
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


def _git_executable() -> str:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git not found")
    return git


def _git_head() -> str:
    return subprocess.run(
        [_git_executable(), "rev-parse", "HEAD"],
        cwd=matchlib.REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _git_changed_paths(pathspec: str) -> list[str]:
    result = subprocess.run(
        [
            _git_executable(),
            "status",
            "--short",
            "--no-renames",
            "--untracked-files=all",
            "--",
            pathspec,
        ],
        cwd=matchlib.REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    paths: list[str] = []
    for line in result.stdout.splitlines():
        path = line[3:]
        if " -> " in path:
            path = path.rsplit(" -> ", 1)[1]
        paths.append(path)
    return paths


def _git_changed_paths_since(revision: str, pathspec: str) -> list[str]:
    result = subprocess.run(
        [
            _git_executable(),
            "diff",
            "--no-renames",
            "--name-only",
            f"{revision}...HEAD",
            "--",
            pathspec,
        ],
        cwd=matchlib.REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.splitlines()


def _matching_changed_paths(match_root: Path, *, base_commit: str | None = None) -> list[str]:
    pathspec = str(match_root / "scratches")
    paths = set(_git_changed_paths(pathspec))
    if base_commit is not None:
        paths.update(_git_changed_paths_since(base_commit, pathspec))
    return sorted(paths)


def _batch_changed_paths(*, base_commit: str | None = None) -> list[str]:
    paths = set(_git_changed_paths("."))
    if base_commit is not None:
        paths.update(_git_changed_paths_since(base_commit, "."))
    return sorted(paths)


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
    scope: Literal["port", "all"] = typer.Option(
        matchlib.DEFAULT_MATCH_SCOPE,
        "--scope",
        help="matching ownership scope",
    ),
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
            scope=scope,
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


@match_app.command("provenance")
def cmd_match_provenance(
    manifest: Path = typer.Option(
        provenance.DEFAULT_PROVENANCE_PATH,
        "--manifest",
        help="library provenance manifest",
    ),
    as_json: bool = typer.Option(False, "--json", help="emit machine-readable JSON"),
    check: bool = typer.Option(False, "--check", help="fail when any provenance check fails"),
) -> None:
    """Verify embedded and dynamically linked library provenance."""
    try:
        report = provenance.validate_library_provenance(manifest)
    except Exception as exc:
        typer.echo(f"provenance failed: {str(exc).splitlines()[0]}", err=True)
        raise typer.Exit(code=2) from exc
    if as_json:
        typer.echo(json.dumps(provenance.provenance_report_payload(report), indent=2, sort_keys=True))
    else:
        typer.echo(provenance.render_provenance_report(report))
    if check and not report.ok:
        raise typer.Exit(code=1)


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
    scope: Literal["port", "all"] = typer.Option(
        matchlib.DEFAULT_MATCH_SCOPE,
        "--scope",
        help="matching ownership scope",
    ),
    recovery: str | None = typer.Option(None, "--recovery", help="comma-separated recovery states"),
    residual: str | None = typer.Option(None, "--residual", help="comma-separated residual kinds"),
) -> None:
    """Compile all scratches and print their current match scores."""
    statuses = matchlib.collect_scratch_statuses(
        match_root,
        compiler=compiler,
        cflags=cflags,
        jobs=jobs,
        scope=scope,
    )
    totals = matchlib.collect_image_totals(statuses, scope=scope)
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
    recoveries = _parse_csv(recovery)
    if recoveries is not None:
        allowed_recoveries = {"exact", "incomplete", "semantic-complete", "unspecified"}
        unknown_recoveries = recoveries - allowed_recoveries
        if unknown_recoveries:
            raise typer.BadParameter(
                f"unknown recovery states: {', '.join(sorted(unknown_recoveries))}",
                param_hint="--recovery",
            )
        selected_statuses = [
            status for status in selected_statuses if matchlib.scratch_recovery(status) in recoveries
        ]
    residuals = _parse_csv(residual)
    if residuals is not None:
        unknown_residuals = residuals - matchlib.RESIDUAL_VALUES
        if unknown_residuals:
            raise typer.BadParameter(
                f"unknown residual kinds: {', '.join(sorted(unknown_residuals))}",
                param_hint="--residual",
            )
        selected_statuses = [
            status for status in selected_statuses if residuals.intersection(status.config.residuals)
        ]
    selected_statuses = matchlib.sort_scratch_statuses(selected_statuses, sort_by=sort_by)
    if limit is not None:
        selected_statuses = selected_statuses[:limit]

    if as_json:
        typer.echo(
            json.dumps(
                {
                    "scope": scope,
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
        write.write_text(
            matchlib.render_status_markdown(statuses, totals, scope=scope),
            encoding="utf-8",
        )
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
    scope: Literal["port", "all"] = typer.Option(
        matchlib.DEFAULT_MATCH_SCOPE,
        "--scope",
        help="matching ownership scope",
    ),
) -> None:
    """Rank every native function by address-keyed recovery opportunity."""
    statuses = matchlib.collect_scratch_statuses(
        match_root,
        compiler=compiler,
        cflags=cflags,
        jobs=jobs,
        scope=scope,
    )
    rows = matchlib.collect_triage_rows(
        statuses,
        images=(image,) if image is not None else None,
        scope=scope,
    )
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
                    "scope": scope,
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


@match_app.command("shard")
def cmd_match_shard(
    workers: int = typer.Option(..., "--workers", min=1, help="number of disjoint worker claims"),
    match_root: Path = typer.Option(matchlib.DEFAULT_MATCH_ROOT, "--match-root", help="tools/match root"),
    scope: Literal["port", "all"] = typer.Option(
        matchlib.DEFAULT_MATCH_SCOPE,
        "--scope",
        help="matching ownership scope",
    ),
    jobs: int = typer.Option(matchlib.DEFAULT_MATCH_JOBS, "--jobs", "-j", min=1, help="parallel status jobs"),
    image: str | None = typer.Option(None, "--image", help="restrict targets to one image"),
    state: str = typer.Option("missing,wip", "--state", help="comma-separated target states"),
    min_bytes: int = typer.Option(0, "--min-bytes", min=0, help="minimum native function bytes"),
    limit: int | None = typer.Option(None, "--limit", min=1, help="maximum targets to assign"),
    output_directory: Path | None = typer.Option(None, "--out", help="ignored plan/claim directory"),
    as_json: bool = typer.Option(False, "--json", help="emit the complete plan"),
) -> None:
    """Create deterministic, disjoint target claims for a worker batch."""
    states = _parse_csv(state) or set()
    unknown_states = states - {"match", "audit", "wip", "error", "missing"}
    if unknown_states:
        raise typer.BadParameter(
            f"unknown states: {', '.join(sorted(unknown_states))}",
            param_hint="--state",
        )
    errors = matchlib.validate_matching_workspace(match_root, scope=scope)
    if errors:
        for error in errors:
            typer.echo(error, err=True)
        raise typer.Exit(code=1)
    changed_paths = _batch_changed_paths()
    if changed_paths:
        typer.echo("shard requires a clean repository:", err=True)
        for path in changed_paths[:20]:
            typer.echo(f"  {path}", err=True)
        raise typer.Exit(code=1)
    statuses = matchlib.collect_scratch_statuses(match_root, jobs=jobs, scope=scope)
    rows = matchlib.collect_triage_rows(
        statuses,
        images=(image,) if image is not None else None,
        scope=scope,
    )
    rows = [
        row
        for row in rows
        if row.state in states and row.target_size >= min_bytes
    ]
    rows = matchlib.sort_triage_rows(rows, sort_by="fuzzy-gap")
    if limit is not None:
        rows = rows[:limit]
    plan = matchlib.build_match_shard_plan(
        rows,
        workers=workers,
        scope=scope,
        base_commit=_git_head(),
        match_root=match_root,
        filters={
            "image": image,
            "states": sorted(states),
            "min_bytes": min_bytes,
            "limit": limit,
        },
    )
    output_directory = output_directory or match_root / ".cache" / "shards"
    claim_errors = matchlib.validate_match_claim(plan, match_root=match_root, scope=scope)
    if claim_errors:
        for error in claim_errors:
            typer.echo(error, err=True)
        raise typer.Exit(code=1)
    plan_path, claim_paths = matchlib.write_match_shard_plan(plan, output_directory.resolve())
    if as_json:
        typer.echo(json.dumps(plan, indent=2, sort_keys=True))
        return
    typer.echo(
        f"scope={scope} targets={plan['target_count']} workers={workers} "
        f"plan={plan_path}",
    )
    for assignment, claim_path in zip(plan["assignments"], claim_paths, strict=True):
        typer.echo(
            f"{assignment['worker']}: targets={len(assignment['targets'])} "
            f"gap={assignment['estimated_gap_bytes']:.0f} claim={claim_path}",
        )


@match_app.command("inspect")
def cmd_match_inspect(
    query: str = typer.Argument(..., help="function name, alias, address, or scratch directory/name"),
    image: str = typer.Option(matchlib.DEFAULT_IMAGE_NAME, "--image", help="target image"),
    match_root: Path = typer.Option(matchlib.DEFAULT_MATCH_ROOT, "--match-root", help="tools/match root"),
    scope: Literal["port", "all"] = typer.Option(
        matchlib.DEFAULT_MATCH_SCOPE,
        "--scope",
        help="matching ownership scope",
    ),
    jobs: int = typer.Option(matchlib.DEFAULT_MATCH_JOBS, "--jobs", "-j", min=1, help="parallel scratch jobs"),
    max_regions: int = typer.Option(1, "--max-regions", min=0, help="bounded mismatch regions"),
    binja_live: bool = typer.Option(False, "--binja-live", help="save a bounded Binary Ninja evidence bundle"),
    as_json: bool = typer.Option(False, "--json", help="emit machine-readable JSON"),
) -> None:
    """Join matcher state with Binary Ninja, IDA, and Ghidra evidence."""
    try:
        target = matchlib.inspect_match_function(
            query,
            image=image,
            scope=scope,
            match_root=match_root,
        )
        configs = matchlib.find_scratch_configs_for_target(
            match_root,
            image=str(target["image"]),
            address=int(target["address"]),
            scope=scope,
        )
        statuses = matchlib.collect_scratch_statuses(
            match_root,
            jobs=jobs,
            scope=scope,
            directories=[config.directory for config in configs],
        )
        payload = matchlib.inspect_match_function(
            query,
            image=image,
            scope=scope,
            match_root=match_root,
            statuses=statuses,
        )
        scratches = payload["scratches"]
        if max_regions and scratches and scratches[0]["state"] != "match":
            config = matchlib.load_scratch_config(Path(scratches[0]["scratch"]))
            obj_path = matchlib.compile_scratch(config, match_root)
            result = matchlib.run_match(
                obj_path=obj_path,
                function=config.function,
                image_path=matchlib.default_image_path(config.image),
                functions_path=matchlib.default_functions_path(config.image),
                metadata_path=matchlib.default_metadata_path(config.image),
                symbol_name=config.symbol,
                end_va=config.end_va,
                reference_aliases=config.reference_aliases,
                scope=scope,
            )
            payload["mismatch_evidence"] = matchlib.match_result_payload(
                result,
                max_regions=max_regions,
            )
        if binja_live:
            address = int(payload["address"])
            program = str(payload["image"])
            bundle_path = (
                match_root
                / ".cache"
                / "evidence"
                / program
                / f"0x{address:08x}.json"
            ).resolve()
            bundle_path.parent.mkdir(parents=True, exist_ok=True)
            command = [
                "bn",
                "bundle",
                "function",
                f"0x{address:08x}",
                "--target",
                f"{program}.bndb",
                "--out",
                str(bundle_path),
            ]
            subprocess.run(command, cwd=matchlib.REPO_ROOT, check=True, capture_output=True, text=True)
            payload["binary_ninja"]["bundle_path"] = str(bundle_path)
    except Exception as exc:
        typer.echo(f"inspect failed: {str(exc).splitlines()[0]}", err=True)
        raise typer.Exit(code=2) from exc

    if as_json:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    typer.echo(
        f"{payload['function']} @ 0x{payload['address']:08x} "
        f"[{payload['image']}, scope={payload['scope']}, bytes={payload['size']}]",
    )
    canonical = payload["canonical"]
    if canonical:
        if canonical.get("signature"):
            typer.echo(f"canonical: {canonical['signature']}")
        if canonical.get("comment"):
            typer.echo(f"  {canonical['comment']}")
    notes = payload["annotations"].get("notes", [])
    if notes:
        typer.echo("annotations:")
        for note in notes:
            typer.echo(f"  - {note}")
    typer.echo("binary-ninja (preferred live view):")
    for name, command in payload["binary_ninja"]["commands"].items():
        typer.echo(f"  {name}: {command}")
    if payload["binary_ninja"].get("bundle_path"):
        typer.echo(f"  saved: {payload['binary_ninja']['bundle_path']}")
    for tool in ("ida", "ghidra"):
        view = payload["observed"][tool]
        function = view["function"]
        if function is None:
            typer.echo(f"{tool}: missing ({view['path']})")
            continue
        typer.echo(f"{tool}: {function.get('name', '<unnamed>')} ({view['path']})")
        if function.get("signature"):
            typer.echo(f"  {function['signature']}")
        calls = function.get("calls") or []
        if calls:
            typer.echo(f"  calls: {', '.join(map(str, calls[:12]))}")
    if payload["ghidra_overlay"]:
        typer.echo(f"ghidra overlay: {len(payload['ghidra_overlay'])} local renames")
    if scratches:
        typer.echo("matcher:")
        for scratch in scratches:
            ratio = "-" if scratch["match_ratio"] is None else f"{scratch['match_ratio']:.2%}"
            typer.echo(
                f"  {scratch['state']} {Path(scratch['scratch']).name} "
                f"match={ratio} recovery={scratch['recovery']} "
                f"residual={','.join(scratch['residuals']) or '-'}",
            )
    else:
        typer.echo("matcher: missing scratch")
    evidence = payload.get("mismatch_evidence")
    if evidence:
        for index, region in enumerate(evidence["regions"], start=1):
            typer.echo(
                f"mismatch {index}: target={region['target_instructions']['start']}:"
                f"{region['target_instructions']['end']} "
                f"candidate={region['candidate_instructions']['start']}:"
                f"{region['candidate_instructions']['end']} "
                f"hints={','.join(region['hints'])}",
            )


@match_app.command("worker-check")
def cmd_match_worker_check(
    claim: Path = typer.Argument(..., help="worker claim JSON from `match shard`"),
    match_root: Path = typer.Option(matchlib.DEFAULT_MATCH_ROOT, "--match-root", help="tools/match root"),
    jobs: int = typer.Option(matchlib.DEFAULT_MATCH_JOBS, "--jobs", "-j", min=1, help="parallel target jobs"),
    output: Path | None = typer.Option(None, "--out", help="ignored worker report path"),
    require_handled: bool = typer.Option(
        False,
        "--require-handled",
        help="fail if any claimed target still has no scratch",
    ),
    as_json: bool = typer.Option(False, "--json", help="emit the complete report"),
) -> None:
    """Validate only one worker's claimed scratches without touching STATUS.md."""
    try:
        claim_payload = matchlib.load_match_claim(claim.resolve())
        if claim_payload.get("kind") != matchlib.WORKER_CLAIM_KIND:
            raise ValueError("worker-check requires a worker claim, not a shard plan")
        scope = str(claim_payload.get("scope", ""))
        errors = matchlib.validate_match_claim(
            claim_payload,
            match_root=match_root,
            scope=scope,
        )
        expected_scratches = matchlib.claimed_scratch_paths(claim_payload)
        changed_paths: list[str] = []
        if not errors:
            changed_paths = _batch_changed_paths(
                base_commit=str(claim_payload["base_commit"]),
            )
            errors.extend(
                matchlib.validate_claimed_changes(
                    claim_payload,
                    changed_paths,
                    match_root=match_root,
                ),
            )

        existing_directories = (
            [
                match_root / scratch
                for scratch in sorted(expected_scratches)
                if (match_root / scratch / "scratch.conf").exists()
            ]
            if not errors
            else []
        )
        statuses = (
            []
            if errors
            else matchlib.collect_scratch_statuses(
                match_root,
                jobs=jobs,
                scope=scope,
                directories=existing_directories,
            )
        )
        statuses_by_directory = {
            str(status.config.directory.resolve().relative_to(match_root.resolve())): status
            for status in statuses
        }
        targets: list[dict[str, Any]] = []
        for _worker, target in matchlib.match_claim_targets(claim_payload):
            scratch = str(target["scratch"])
            status = statuses_by_directory.get(scratch)
            targets.append(
                {
                    **target,
                    "handled": status is not None,
                    "status": (
                        matchlib.scratch_status_payload(status)
                        if status is not None
                        else None
                    ),
                },
            )
        state_counts = {
            state: sum(
                target["status"] is not None
                and target["status"]["state"] == state
                for target in targets
            )
            for state in ("match", "audit", "wip", "error")
        }
        unhandled = sum(not bool(target["handled"]) for target in targets)
        report: dict[str, Any] = {
            "schema": matchlib.SHARD_SCHEMA,
            "kind": "crimson-match-worker-report",
            "scope": scope,
            "worker": claim_payload["worker"],
            "claim": str(claim.resolve()),
            "summary": {
                "targets": len(targets),
                "handled": len(targets) - unhandled,
                "unhandled": unhandled,
                "states": state_counts,
                "errors": len(errors),
            },
            "changed_paths": changed_paths,
            "errors": errors,
            "targets": targets,
        }
        output = output or (
            match_root
            / ".cache"
            / "reports"
            / f"{claim_payload['worker']}.json"
        )
        matchlib.write_match_json(output.resolve(), report)
    except Exception as exc:
        typer.echo(f"worker check failed: {str(exc).splitlines()[0]}", err=True)
        raise typer.Exit(code=2) from exc

    if as_json:
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
    else:
        typer.echo(
            f"worker={report['worker']} targets={len(targets)} "
            f"handled={len(targets) - unhandled} unhandled={unhandled} "
            f"errors={len(errors)} report={output.resolve()}",
        )
        typer.echo(
            "states="
            + "/".join(
                f"{state}:{count}"
                for state, count in state_counts.items()
            ),
        )
        for error in report["errors"]:
            typer.echo(str(error), err=True)
    if errors or state_counts["error"]:
        raise typer.Exit(code=1)
    if require_handled and unhandled:
        raise typer.Exit(code=1)


@match_app.command("checkpoint")
def cmd_match_checkpoint(
    match_root: Path = typer.Option(matchlib.DEFAULT_MATCH_ROOT, "--match-root", help="tools/match root"),
    scope: Literal["port", "all"] = typer.Option(
        matchlib.DEFAULT_MATCH_SCOPE,
        "--scope",
        help="matching ownership scope",
    ),
    jobs: int = typer.Option(matchlib.DEFAULT_MATCH_JOBS, "--jobs", "-j", min=1, help="parallel scratch jobs"),
    write: Path = typer.Option(
        matchlib.DEFAULT_MATCH_ROOT / "STATUS.md",
        "--write",
        help="write canonical markdown status",
    ),
    claims: Path | None = typer.Option(
        None,
        "--claims",
        help="shard plan whose ownership must cover scratch changes",
    ),
) -> None:
    """Validate scope, refresh status, and run repository diff checks."""
    errors = matchlib.validate_matching_workspace(match_root, scope=scope)
    scratch_changed_paths = _matching_changed_paths(match_root)
    changed_paths = scratch_changed_paths
    claim_errors: list[str] = []
    if claims is not None:
        try:
            claim_payload = matchlib.load_match_claim(claims.resolve())
            if claim_payload.get("kind") != matchlib.SHARD_PLAN_KIND:
                raise ValueError("checkpoint requires a shard plan, not a worker claim")
            claim_errors.extend(
                matchlib.validate_match_claim(
                    claim_payload,
                    match_root=match_root,
                    scope=scope,
                ),
            )
            if not claim_errors:
                changed_paths = _batch_changed_paths(
                    base_commit=str(claim_payload["base_commit"]),
                )
                try:
                    status_path = write.resolve().relative_to(matchlib.REPO_ROOT).as_posix()
                except ValueError:
                    status_path = str(write.resolve())
                claim_errors.extend(
                    matchlib.validate_claimed_changes(
                        claim_payload,
                        changed_paths,
                        match_root=match_root,
                        allowed_paths=[status_path],
                    ),
                )
        except Exception as exc:
            claim_errors.append(str(exc).splitlines()[0])
    statuses = matchlib.collect_scratch_statuses(match_root, jobs=jobs, scope=scope)
    totals = matchlib.collect_image_totals(statuses, scope=scope)
    write.parent.mkdir(parents=True, exist_ok=True)
    write.write_text(
        matchlib.render_status_markdown(statuses, totals, scope=scope),
        encoding="utf-8",
    )

    git = _git_executable()
    diff_checks = [
        subprocess.run(
            [git, "diff", *arguments, "--check"],
            cwd=matchlib.REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        for arguments in ([], ["--cached"])
    ]
    evaluation_errors = [status for status in statuses if status.state == "error"]

    typer.echo(f"scope={scope}")
    typer.echo(matchlib.render_status_summary(totals))
    typer.echo(f"status={write}")
    typer.echo(f"changed_scratch_files={len(scratch_changed_paths)}")
    if claims is not None:
        typer.echo(f"changed_batch_files={len(changed_paths)}")
    typer.echo(
        f"scope_errors={len(errors)} claim_errors={len(claim_errors)} "
        f"evaluation_errors={len(evaluation_errors)}",
    )
    for error in errors[:20]:
        typer.echo(f"  {error}", err=True)
    for error in claim_errors[:20]:
        typer.echo(f"  {error}", err=True)
    for diff_check in diff_checks:
        if diff_check.stdout:
            typer.echo(diff_check.stdout.rstrip(), err=True)
        if diff_check.stderr:
            typer.echo(diff_check.stderr.rstrip(), err=True)
    if (
        errors
        or claim_errors
        or evaluation_errors
        or any(diff_check.returncode for diff_check in diff_checks)
    ):
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
    scope: Literal["port", "all"] = typer.Option(
        matchlib.DEFAULT_MATCH_SCOPE,
        "--scope",
        help="matching ownership scope",
    ),
) -> None:
    """Report what each normalized ADDR refers to on both sides."""
    statuses = matchlib.collect_scratch_statuses(
        match_root,
        compiler=compiler,
        cflags=cflags,
        jobs=jobs,
        scope=scope,
    )
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
