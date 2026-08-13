from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import typer

from .. import library_match, match_experiments, match_mutation, mod_sdk
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
    object_extent: Literal["symbol", "section-tail"] = typer.Option(
        "symbol",
        "--object-extent",
        help="candidate extraction extent",
    ),
    object_end_symbol: str | None = typer.Option(
        None,
        "--object-end-symbol",
        help="exclusive COFF code symbol boundary",
    ),
    object_size: int | None = typer.Option(
        None,
        "--object-size",
        min=1,
        help="explicit candidate byte size for a COFF code label",
    ),
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
            object_extent=object_extent,
            object_end_symbol=object_end_symbol,
            object_size=object_size,
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
            object_extent=config.archive_extent,
            object_end_symbol=config.archive_end_symbol,
            object_size=config.archive_size,
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
    object_extent: Literal["symbol", "section-tail"] = typer.Option(
        "symbol",
        "--object-extent",
        help="candidate extraction extent",
    ),
    object_end_symbol: str | None = typer.Option(
        None,
        "--object-end-symbol",
        help="exclusive COFF code symbol boundary",
    ),
    object_size: int | None = typer.Option(
        None,
        "--object-size",
        min=1,
        help="explicit candidate byte size for a COFF code label",
    ),
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
            object_extent=object_extent,
            object_end_symbol=object_end_symbol,
            object_size=object_size,
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


@match_app.command("listing")
def cmd_match_listing(
    directory: Path = typer.Argument(..., help="source-backed scratch directory"),
    match_root: Path = typer.Option(
        matchlib.DEFAULT_MATCH_ROOT,
        "--match-root",
        help="tools/match root",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        help="output .cod path; defaults to the ignored match cache",
    ),
    as_json: bool = typer.Option(False, "--json", help="emit machine-readable JSON"),
) -> None:
    """Emit a source/assembly compiler listing after proving object equivalence."""
    try:
        config = matchlib.load_scratch_config(directory.resolve())
        result = matchlib.generate_compiler_listing(
            config,
            match_root,
            output=output,
        )
    except Exception as exc:
        typer.echo(f"listing failed: {str(exc).splitlines()[0]}", err=True)
        raise typer.Exit(code=2) from exc
    if as_json:
        typer.echo(json.dumps(matchlib.compiler_listing_payload(result), indent=2, sort_keys=True))
    else:
        typer.echo(matchlib.render_compiler_listing_result(result))


@match_app.command("validate")
def cmd_match_validate(
    source: Path = typer.Argument(..., help="scratch source file or directory"),
) -> None:
    """Reject fakematching-only scratch constructs."""
    try:
        if source.is_dir():
            config = matchlib.load_scratch_config(source)
            matchlib.validate_scratch_config(config)
        else:
            matchlib.validate_scratch_source(source)
    except (OSError, ValueError) as exc:
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


@match_app.command("mod-sdk")
def cmd_match_mod_sdk(
    sdk: Path | None = typer.Option(
        None,
        "--sdk",
        help="MOD SDK directory or cl_mod_sdk_v1.zip; defaults to CRIMSON_MOD_SDK or Downloads",
    ),
    manifest: Path = typer.Option(
        mod_sdk.DEFAULT_MOD_SDK_MANIFEST,
        "--manifest",
        help="pinned MOD SDK provenance manifest",
    ),
    match_root: Path = typer.Option(
        matchlib.DEFAULT_MATCH_ROOT,
        "--match-root",
        help="tools/match root containing cl.sh and compiler profiles",
    ),
    provenance_only: bool = typer.Option(
        False,
        "--provenance-only",
        help="verify package, recipe, DLL, and Rich metadata without recompiling exports",
    ),
    as_json: bool = typer.Option(False, "--json", help="emit machine-readable JSON"),
    check: bool = typer.Option(False, "--check", help="fail when provenance or calibration differs"),
) -> None:
    """Verify the 2003 MOD SDK and calibrate its source/compiler pair."""
    try:
        report = mod_sdk.validate_mod_sdk(
            sdk,
            manifest_path=manifest,
            match_root=match_root,
            compile_exports=not provenance_only,
        )
    except Exception as exc:
        typer.echo(f"MOD SDK calibration failed: {str(exc).splitlines()[0]}", err=True)
        raise typer.Exit(code=2) from exc
    if as_json:
        typer.echo(json.dumps(mod_sdk.mod_sdk_report_payload(report), indent=2, sort_keys=True))
    else:
        typer.echo(mod_sdk.render_mod_sdk_report(report))
    if check and not report.ok:
        raise typer.Exit(code=1)


@match_app.command("archive")
def cmd_match_archive(
    archive: Path = typer.Argument(..., help="candidate COFF .lib archive"),
    image: Path = typer.Option(matchlib.DEFAULT_IMAGE_PATH, "--image", help="target PE image"),
    functions: Path | None = typer.Option(None, "--functions", help="IDA functions manifest"),
    metadata: Path | None = typer.Option(None, "--metadata", help="IDA metadata manifest"),
    missing_scratches: bool = typer.Option(
        False,
        "--missing-scratches",
        help="scan only target addresses with no evaluated scratch",
    ),
    match_root: Path = typer.Option(
        matchlib.DEFAULT_MATCH_ROOT,
        "--match-root",
        help="tools/match root used by --missing-scratches",
    ),
    jobs: int = typer.Option(8, "--jobs", "-j", min=1, help="parallel scratch jobs"),
    start: str = typer.Option(..., "--start", help="inclusive target range start VA"),
    end: str = typer.Option(..., "--end", help="exclusive target range end VA"),
    expected_sha256: str | None = typer.Option(
        None,
        "--expected-sha256",
        help="expected archive SHA-256",
    ),
    show_matches: bool = typer.Option(False, "--show-matches", help="list exact function matches"),
    show_reference_bindings: bool = typer.Option(
        False,
        "--show-reference-bindings",
        help="list stable addend-normalized object symbols bound to one image address",
    ),
    resolve_known_references: bool = typer.Option(
        False,
        "--resolve-known-references",
        help="discard byte-identical candidates contradicted by known relocation targets",
    ),
    limit: int | None = typer.Option(None, "--limit", min=1, help="maximum listed matches"),
    write_scratches: bool = typer.Option(
        False,
        "--write-scratches",
        help="write strictly unique matches as pinned scratch configs",
    ),
    write_symbol_unique: bool = typer.Option(
        False,
        "--write-symbol-unique",
        help="also write matches whose duplicate members share one symbol",
    ),
    write_reference_aliases: bool = typer.Option(
        False,
        "--write-reference-aliases",
        help="add aliases for stable addend-normalized references to known image symbols",
    ),
    scratch_note_prefix: str = typer.Option(
        "archive",
        "--scratch-note-prefix",
        help="NOTE prefix for generated scratch configs",
    ),
    as_json: bool = typer.Option(False, "--json", help="emit machine-readable JSON"),
    check: bool = typer.Option(False, "--check", help="fail on hash mismatch or zero matches"),
) -> None:
    """Match historical COFF library members directly against a linked PE range."""
    if write_scratches and not missing_scratches:
        raise typer.BadParameter("--write-scratches requires --missing-scratches")
    if write_scratches and expected_sha256 is None:
        raise typer.BadParameter("--write-scratches requires --expected-sha256")
    if write_symbol_unique and not write_scratches:
        raise typer.BadParameter("--write-symbol-unique requires --write-scratches")
    if write_reference_aliases and not write_scratches:
        raise typer.BadParameter("--write-reference-aliases requires --write-scratches")
    image_name = image.name
    try:
        excluded_addresses: frozenset[int] = frozenset()
        if missing_scratches:
            statuses = matchlib.collect_scratch_statuses(match_root, jobs=jobs, scope="all")
            excluded_addresses = frozenset(
                status.address
                for status in statuses
                if status.config.image == image_name and status.address is not None
            )
        report = library_match.match_coff_archive(
            archive,
            image_path=image,
            functions_path=functions or matchlib.default_functions_path(image_name),
            metadata_path=metadata or matchlib.default_metadata_path(image_name),
            range_start=matchlib.parse_int(start),
            range_end=matchlib.parse_int(end),
            excluded_addresses=excluded_addresses,
            resolve_known_references=resolve_known_references,
        )
    except Exception as exc:
        typer.echo(f"archive match failed: {str(exc).splitlines()[0]}", err=True)
        raise typer.Exit(code=2) from exc

    hash_ok = expected_sha256 is None or report.archive_sha256 == expected_sha256.lower()
    reference_bindings: tuple[library_match.ArchiveReferenceBinding, ...] = ()
    if show_reference_bindings:
        try:
            reference_bindings = library_match.infer_archive_reference_bindings(
                report,
                functions_path=functions or matchlib.default_functions_path(image_name),
                metadata_path=metadata or matchlib.default_metadata_path(image_name),
                include_symbol_unique=write_symbol_unique,
            )
        except Exception as exc:
            typer.echo(f"archive reference binding failed: {str(exc).splitlines()[0]}", err=True)
            raise typer.Exit(code=2) from exc
    written_scratches: tuple[library_match.ArchiveScratchWrite, ...] = ()
    if write_scratches:
        try:
            assert expected_sha256 is not None
            written_scratches = library_match.write_archive_scratch_configs(
                report,
                match_root=match_root,
                expected_sha256=expected_sha256,
                note_prefix=scratch_note_prefix,
                include_symbol_unique=write_symbol_unique,
                infer_reference_aliases=write_reference_aliases,
                functions_path=functions or matchlib.default_functions_path(image_name),
                metadata_path=metadata or matchlib.default_metadata_path(image_name),
            )
        except Exception as exc:
            typer.echo(f"archive scratch write failed: {str(exc).splitlines()[0]}", err=True)
            raise typer.Exit(code=2) from exc
    if as_json:
        payload = library_match.archive_match_payload(report, limit=limit)
        payload["expected_sha256"] = expected_sha256
        payload["hash_ok"] = hash_ok
        payload["filters"] = {"missing_scratches": missing_scratches}
        if resolve_known_references:
            payload["filters"]["known_references"] = True
        if show_reference_bindings:
            payload["reference_bindings"] = library_match.archive_reference_bindings_payload(
                reference_bindings,
                limit=limit,
            )
        payload["written_scratches"] = {
            "count": len(written_scratches),
            "include_symbol_unique": write_symbol_unique,
            "infer_reference_aliases": write_reference_aliases,
            "directories": [
                str(write.directory.relative_to(match_root))
                for write in written_scratches
            ],
        }
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        rendered = library_match.render_archive_match_report(
            report,
            show_matches=show_matches,
            limit=limit,
        )
        if show_reference_bindings:
            rendered += "\n" + library_match.render_archive_reference_bindings(
                reference_bindings,
                limit=limit,
            )
        typer.echo(rendered)
        if not hash_ok:
            typer.echo(
                f"hash mismatch: expected={expected_sha256} actual={report.archive_sha256}",
                err=True,
            )
        if write_scratches:
            typer.echo(
                f"written_scratch_configs={len(written_scratches)} "
                f"root={match_root / 'scratches'}",
            )
    if check and (not hash_ok or report.matched_functions == 0):
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
            "schema": match_experiments.EXPERIMENT_SCHEMA,
            "kind": "probe",
            "recorded_at": datetime.now(UTC).isoformat(),
            "baseline_epoch": matchlib.scratch_experiment_epoch(
                result.baseline.config,
                match_root,
            ),
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


@match_app.command("mutate")
def cmd_match_mutate(
    directory: Path = typer.Argument(..., help="scratch directory containing scratch.conf"),
    spec: Path = typer.Option(..., "--spec", help="JSON mutation plan"),
    source: Path | None = typer.Option(
        None,
        "--source",
        help="scratch source or included match header to mutate (default: configured source)",
    ),
    match_root: Path = typer.Option(matchlib.DEFAULT_MATCH_ROOT, "--match-root", help="tools/match root"),
    compiler: str | None = typer.Option(None, "--compiler", help="profile used for baseline and variants"),
    cflags: str | None = typer.Option(None, "--cflags", help="flags used for baseline and variants"),
    max_changes: int = typer.Option(1, "--max-changes", min=1, help="maximum mutation sites per variant"),
    max_variants: int = typer.Option(256, "--max-variants", min=1, help="bounded variant budget"),
    jobs: int = typer.Option(matchlib.DEFAULT_MATCH_JOBS, "--jobs", "-j", min=1, help="parallel variant jobs"),
    stop_on_improvement: bool = typer.Option(
        False,
        "--stop-on-improvement",
        help="stop scheduling batches after the first improving batch",
    ),
    time_budget: float | None = typer.Option(
        None,
        "--time-budget",
        min=0.1,
        help="soft variant wall-clock budget in seconds; running batches finish",
    ),
    top: int = typer.Option(20, "--top", min=1, help="maximum ranked variants to print"),
    write_best: Path | None = typer.Option(
        None,
        "--write-best",
        help="write the best tradeoff-free source only when it improves the baseline",
    ),
    require_improvement: bool = typer.Option(
        False,
        "--require-improvement",
        help="fail when no tradeoff-free variant improves the baseline",
    ),
    record: bool = typer.Option(False, "--record", help="append the complete sweep to experiments.jsonl"),
    as_json: bool = typer.Option(False, "--json", help="emit machine-readable JSON"),
) -> None:
    """Compile and rank bounded source mutations without touching tracked files."""
    try:
        config = matchlib.load_scratch_config(directory.resolve())
        mutation_spec = match_mutation.load_mutation_spec(spec.resolve())
        source_path = source.resolve() if source is not None else (config.directory / config.source).resolve()
        if write_best is not None and write_best.resolve() == source_path:
            raise ValueError("--write-best cannot overwrite the mutated source")
        source_text = source_path.read_text(encoding="utf-8")
        sweep = match_mutation.evaluate_mutation_sweep(
            config,
            mutation_spec,
            source_text=source_text,
            source_path=source_path,
            match_root=match_root,
            compiler=compiler,
            cflags=cflags,
            max_changes=max_changes,
            max_variants=max_variants,
            jobs=jobs,
            stop_on_improvement=stop_on_improvement,
            time_budget=time_budget,
        )
    except Exception as exc:
        typer.echo(f"mutation sweep failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    written_to: str | None = None
    if write_best is not None and sweep.best_improves:
        assert sweep.winner is not None
        write_best.parent.mkdir(parents=True, exist_ok=True)
        write_best.write_text(sweep.winner.variant.source_text, encoding="utf-8")
        written_to = str(write_best)

    recorded_to: str | None = None
    if record:
        record_path = config.directory / "experiments.jsonl"
        record_payload = {
            "kind": "mutation-sweep",
            "recorded_at": datetime.now(UTC).isoformat(),
            "baseline_epoch": matchlib.scratch_experiment_epoch(
                sweep.baseline.config,
                match_root,
            ),
            "best_source_written_to": written_to,
            "mutation_source": str(source_path),
            **match_mutation.mutation_sweep_payload(sweep),
        }
        with record_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record_payload, separators=(",", ":"), sort_keys=True) + "\n")
        recorded_to = str(record_path)

    if as_json:
        payload = match_mutation.mutation_sweep_payload(sweep, limit=top)
        payload["best_source_written_to"] = written_to
        payload["mutation_source"] = str(source_path)
        payload["recorded_to"] = recorded_to
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        typer.echo(match_mutation.render_mutation_sweep(sweep, limit=top))
        if written_to is not None:
            typer.echo(f"best_source={written_to}")
        elif write_best is not None:
            typer.echo("best_source=not-written (no tradeoff-free improving variant)")
        if recorded_to is not None:
            typer.echo(f"recorded={recorded_to}")

    if sweep.baseline.state == "error" or all(
        evaluation.status.state == "error" for evaluation in sweep.evaluations
    ):
        raise typer.Exit(code=2)
    if (write_best is not None or require_improvement) and not sweep.best_improves:
        raise typer.Exit(code=1)


@match_app.command("experiments")
def cmd_match_experiments(
    match_root: Path = typer.Option(matchlib.DEFAULT_MATCH_ROOT, "--match-root", help="tools/match root"),
    scratch: list[str] | None = typer.Option(
        None,
        "--scratch",
        help="scratch name, directory, or experiments.jsonl; repeat to restrict",
    ),
    sort_by: Literal[
        "errors",
        "no-improvement",
        "records",
        "repeats",
        "scratch",
        "variants",
    ] = typer.Option("variants", "--sort", help="row ranking"),
    limit: int | None = typer.Option(None, "--limit", min=1, help="maximum rows to display"),
    as_json: bool = typer.Option(False, "--json", help="emit machine-readable JSON"),
    check: bool = typer.Option(False, "--check", help="fail when any log record is malformed"),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="also fail on current-baseline probe or mutation evaluation errors",
    ),
) -> None:
    """Summarize recorded probes and mutation sweeps across scratch logs."""
    try:
        experiment_paths = match_experiments.find_experiment_logs(
            match_root,
            scratch or (),
        )
        current_epochs = matchlib.scratch_experiment_epochs(
            match_root,
            directories=[path.parent for path in experiment_paths],
        )
        payload = match_experiments.summarize_experiments(
            match_root,
            scratches=scratch or (),
            sort_by=sort_by,
            current_epochs=current_epochs,
        )
    except Exception as exc:
        typer.echo(f"experiment summary failed: {str(exc).splitlines()[0]}", err=True)
        raise typer.Exit(code=2) from exc

    if limit is not None:
        payload["rows"] = payload["rows"][:limit]
    payload["selected_rows"] = len(payload["rows"])
    if as_json:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        typer.echo(match_experiments.render_experiment_summary(payload))
        for error in payload["errors"]:
            typer.echo(str(error), err=True)
        for error in payload["strict_errors"]:
            typer.echo(str(error), err=True)
    if ((check or strict) and payload["errors"]) or (strict and payload["strict_errors"]):
        raise typer.Exit(code=1)


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


@match_app.command("compiler-scan")
def cmd_match_compiler_scan(
    match_root: Path = typer.Option(matchlib.DEFAULT_MATCH_ROOT, "--match-root", help="tools/match root"),
    compiler: list[str] | None = typer.Option(
        None,
        "--compiler",
        help="compiler to compare; repeat for a corpus matrix",
    ),
    jobs: int = typer.Option(
        matchlib.DEFAULT_MATCH_JOBS,
        "--jobs",
        "-j",
        min=1,
        help="parallel scratch jobs per compiler",
    ),
    image: str | None = typer.Option(None, "--image", help="restrict to one tracked image"),
    state: str = typer.Option("wip", "--state", help="comma-separated canonical baseline states"),
    scope: Literal["port", "all"] = typer.Option(
        matchlib.DEFAULT_MATCH_SCOPE,
        "--scope",
        help="matching ownership scope",
    ),
    show_all: bool = typer.Option(False, "--all", help="include compiler ties"),
    include_disproven: bool = typer.Option(
        False,
        "--include-disproven",
        help="evaluate profiles rejected by recorded compiler provenance",
    ),
    limit: int | None = typer.Option(None, "--limit", min=1, help="maximum rows to show"),
    as_json: bool = typer.Option(False, "--json", help="emit machine-readable JSON"),
    check: bool = typer.Option(False, "--check", help="fail when any requested profile cannot be evaluated"),
) -> None:
    """Compare canonical scratches across installed compiler profiles."""

    states = _parse_csv(state) or {"wip"}
    unknown_states = states - {"match", "audit", "wip", "error"}
    if unknown_states:
        raise typer.BadParameter(
            f"unknown states: {', '.join(sorted(unknown_states))}",
            param_hint="--state",
        )

    baselines = matchlib.collect_scratch_statuses(
        match_root,
        jobs=jobs,
        scope=scope,
    )
    selected = [
        status
        for status in baselines
        if status.state in states
        and (image is None or status.config.image == image)
        and status.config.archive is None
        and status.config.import_thunk is None
    ]
    compilers = tuple(
        dict.fromkeys(
            compiler
            or matchlib.available_scratch_compilers(match_root)
            or (status.config.compiler for status in selected),
        ),
    )
    profiles: list[matchlib.ScratchStatus] = []
    disproven_skips: list[dict[str, str]] = []
    for profile_compiler in compilers:
        profile_directories: list[Path] = []
        for status in selected:
            if not include_disproven and profile_compiler in status.config.disproven_compilers:
                disproven_skips.append(
                    {
                        "image": status.config.image,
                        "function": status.config.function,
                        "compiler": profile_compiler,
                    },
                )
                continue
            profile_directories.append(status.config.directory)
        if not profile_directories:
            continue
        profiles.extend(
            matchlib.collect_scratch_statuses(
                match_root,
                compiler=profile_compiler,
                jobs=jobs,
                scope=scope,
                directories=profile_directories,
            ),
        )

    rows = matchlib.build_compiler_scan_rows(selected, profiles)
    summary = matchlib.compiler_scan_summary(rows, profiles)
    evaluation_errors = [
        {
            "image": status.config.image,
            "function": status.config.function,
            "compiler": status.config.compiler,
            "cflags": status.config.cflags,
            "error": status.error,
        }
        for status in profiles
        if status.state == "error"
    ]
    visible_rows = rows if show_all else [row for row in rows if row.classification != "tied"]
    if limit is not None:
        visible_rows = visible_rows[:limit]
    provenance_note = (
        "Alternate compiler wins are source-shape search evidence, not object provenance; "
        "verify PE, Rich, COFF, archive, or translation-unit evidence before changing a scratch compiler."
    )

    if as_json:
        typer.echo(
            json.dumps(
                {
                    "scope": scope,
                    "states": sorted(states),
                    "compilers": list(compilers),
                    "summary": summary,
                    "rows": [matchlib.compiler_scan_row_payload(row) for row in visible_rows],
                    "evaluation_errors": evaluation_errors,
                    "disproven_skips": disproven_skips,
                    "provenance_note": provenance_note,
                },
                indent=2,
                sort_keys=True,
            ),
        )
    else:
        if visible_rows:
            typer.echo(matchlib.render_compiler_scan_rows(visible_rows))
        else:
            typer.echo("no exact or improved compiler profiles")
        typer.echo(
            "targets={targets} profiles={profiles} exact={exact} improved={improved} "
            "tied={tied} errors={errors} skipped_disproven={skipped_disproven} "
            "compilers={compilers}".format(
                **summary,
                skipped_disproven=len(disproven_skips),
                compilers=",".join(compilers) or "-",
            ),
        )
        if evaluation_errors:
            typer.echo("profile evaluation errors:")
            for error in evaluation_errors[:20]:
                typer.echo(
                    f"- {error['image']} {error['function']} {error['compiler']}: {error['error']}",
                )
            if len(evaluation_errors) > 20:
                typer.echo(f"- ... and {len(evaluation_errors) - 20} more")
        if disproven_skips:
            typer.echo(
                f"skipped {len(disproven_skips)} profile evaluations rejected by recorded provenance; "
                "pass --include-disproven to inspect them",
            )
        typer.echo(provenance_note)
    if check and summary["errors"]:
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
                    "function_dispositions": (
                        matchlib.matching_scope_function_disposition_payloads(scope)
                    ),
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
            matchlib.render_status_markdown(
                statuses,
                totals,
                scope=scope,
                native_statuses=matchlib.collect_native_link_statuses(
                    scope=scope,
                    allow_absent_toolchain=True,
                ),
            ),
            encoding="utf-8",
        )
    if check:
        metadata_errors = matchlib.validate_scratch_status_metadata(statuses)
        for error in metadata_errors:
            typer.echo(error, err=True)
        if any(status.state == "error" for status in statuses) or metadata_errors:
            raise typer.Exit(code=1)


@match_app.command("resolved-name-audit")
def cmd_match_resolved_name_audit(
    root: Path = typer.Option(matchlib.REPO_ROOT, "--root", help="repository root to scan"),
    name_map: Path = typer.Option(
        matchlib.DEFAULT_NAME_MAP_PATH,
        "--name-map",
        help="curated function-name map",
    ),
    data_map: Path = typer.Option(
        matchlib.DEFAULT_DATA_MAP_PATH,
        "--data-map",
        help="curated data-name map",
    ),
    limit: int | None = typer.Option(None, "--limit", min=1, help="maximum rows to show"),
    summary_only: bool = typer.Option(False, "--summary-only", help="print aggregate debt only"),
    as_json: bool = typer.Option(False, "--json", help="emit machine-readable JSON"),
    rewrite: bool = typer.Option(
        False,
        "--rewrite",
        help="replace unambiguous analyzer labels with curated names or explicit addresses",
    ),
    check: bool = typer.Option(False, "--check", help="fail when resolved labels remain"),
) -> None:
    """Find analyzer identities whose curated identity is already stronger."""

    rows = matchlib.collect_resolved_name_references(
        repo_root=root,
        name_map_path=name_map,
        data_map_path=data_map,
    )
    if rewrite:
        if limit is not None or summary_only or check:
            raise typer.BadParameter(
                "rewriting cannot be combined with limit, summary, or check filters",
                param_hint="--rewrite",
            )
        result = matchlib.rewrite_resolved_name_references(rows, repo_root=root)
        if as_json:
            typer.echo(json.dumps(result, indent=2, sort_keys=True))
        else:
            typer.echo(
                f"files_updated={result['files_updated']} "
                f"references_updated={result['references_updated']} "
                f"rows_skipped={result['rows_skipped']}",
            )
        return
    displayed_rows = rows[:limit] if limit is not None else rows
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "summary": matchlib.resolved_name_reference_summary_payload(rows),
                    "rows": (
                        []
                        if summary_only
                        else [
                            matchlib.resolved_name_reference_payload(row)
                            for row in displayed_rows
                        ]
                    ),
                },
                indent=2,
                sort_keys=True,
            ),
        )
    elif summary_only:
        typer.echo(matchlib.render_resolved_name_reference_summary(rows))
    else:
        typer.echo(matchlib.render_resolved_name_reference_table(displayed_rows))
    if check and rows:
        raise typer.Exit(code=1)


@match_app.command("naming-audit")
def cmd_match_naming_audit(
    match_root: Path = typer.Option(matchlib.DEFAULT_MATCH_ROOT, "--match-root", help="tools/match root"),
    name_map: Path = typer.Option(
        matchlib.DEFAULT_NAME_MAP_PATH,
        "--name-map",
        help="curated function-name map",
    ),
    data_map: Path = typer.Option(
        matchlib.DEFAULT_DATA_MAP_PATH,
        "--data-map",
        help="curated data-name map",
    ),
    naming_hints: Path = typer.Option(
        matchlib.DEFAULT_NAMING_HINTS_PATH,
        "--naming-hints",
        help="address-keyed, evidence-backed naming hints",
    ),
    jobs: int = typer.Option(matchlib.DEFAULT_MATCH_JOBS, "--jobs", "-j", min=1, help="parallel scratch jobs"),
    image: str | None = typer.Option(None, "--image", help="show rows for one image"),
    provider_member: str | None = typer.Option(
        None,
        "--provider-member",
        help="comma-separated archive member paths or basenames",
    ),
    suggested_only: bool = typer.Option(
        False,
        "--suggested-only",
        help="show only deterministic same-provider naming suggestions",
    ),
    apply_suggestions: bool = typer.Option(
        False,
        "--apply-suggestions",
        help="apply selected deterministic suggestions to scratches and the name map",
    ),
    prune_aliases: bool = typer.Option(
        False,
        "--prune-placeholder-aliases",
        help="remove audited analyzer aliases from selected curated-map rows",
    ),
    rewrite_references: bool = typer.Option(
        False,
        "--rewrite-placeholder-references",
        help="replace unambiguous analyzer reference targets with canonical map names",
    ),
    repair_comments: bool = typer.Option(
        False,
        "--repair-provider-comments",
        help="restore exact provider symbols in auto-generated map comments",
    ),
    limit: int | None = typer.Option(None, "--limit", min=1, help="maximum rows to show"),
    summary_only: bool = typer.Option(False, "--summary-only", help="print aggregate naming debt only"),
    as_json: bool = typer.Option(False, "--json", help="emit machine-readable JSON"),
    check: bool = typer.Option(False, "--check", help="fail when selected naming debt remains"),
    scope: Literal["port", "all"] = typer.Option(
        "all",
        "--scope",
        help="matching ownership scope",
    ),
) -> None:
    """Report recovered identities and curated maps with weaker analyzer names."""

    statuses = matchlib.collect_scratch_statuses(match_root, jobs=jobs, scope=scope)
    rows = matchlib.collect_naming_debt(
        statuses,
        name_map_path=name_map,
        naming_hints_path=naming_hints,
        data_map_path=data_map,
    )
    provider_members = _parse_csv(provider_member)
    selected_statuses = [
        status
        for status in statuses
        if (image is None or status.config.image == image)
        and (
            provider_members is None
            or status.config.archive_member in provider_members
            or (
                status.config.archive_member is not None
                and status.config.archive_member.replace("\\", "/").rsplit("/", 1)[-1]
                in provider_members
            )
        )
    ]
    rows = [
        row
        for row in rows
        if (image is None or row.image == image)
        and (
            provider_members is None
            or row.provider_member in provider_members
            or (
                row.provider_member is not None
                and row.provider_member.replace("\\", "/").rsplit("/", 1)[-1]
                in provider_members
            )
        )
        and (not suggested_only or row.suggestion is not None)
    ]
    selected_rows = rows
    if sum((apply_suggestions, prune_aliases, rewrite_references, repair_comments)) > 1:
        raise typer.BadParameter(
            "choose only one naming-audit mutation option",
            param_hint="--apply-suggestions",
        )
    if repair_comments:
        if suggested_only or limit is not None or summary_only or check:
            raise typer.BadParameter(
                "comment repair cannot be combined with suggestion, limit, summary, or check filters",
                param_hint="--repair-provider-comments",
            )
        result = matchlib.repair_provider_comments(selected_statuses, name_map_path=name_map)
        if as_json:
            typer.echo(json.dumps(result, indent=2, sort_keys=True))
        else:
            typer.echo(f"comments_repaired={result['comments_repaired']}")
        return
    if rewrite_references:
        if suggested_only or limit is not None or summary_only or check:
            raise typer.BadParameter(
                "reference rewriting cannot be combined with suggestion, limit, summary, or check filters",
                param_hint="--rewrite-placeholder-references",
            )
        result = matchlib.rewrite_placeholder_references(selected_rows, match_root=match_root)
        if as_json:
            typer.echo(json.dumps(result, indent=2, sort_keys=True))
        else:
            typer.echo(
                f"configs_updated={result['configs_updated']} "
                f"references_updated={result['references_updated']} "
                f"mappings={len(result['mappings'])}",
            )
        return
    if prune_aliases:
        if suggested_only or limit is not None or summary_only or check:
            raise typer.BadParameter(
                "alias pruning cannot be combined with suggestion, limit, summary, or check filters",
                param_hint="--prune-placeholder-aliases",
            )
        result = matchlib.prune_placeholder_aliases(
            selected_rows,
            name_map_path=name_map,
            data_map_path=data_map,
        )
        if as_json:
            typer.echo(json.dumps(result, indent=2, sort_keys=True))
        else:
            typer.echo(
                f"rows_pruned={result['rows_pruned']} aliases_removed={result['aliases_removed']}",
            )
        return
    if apply_suggestions:
        if limit is not None:
            raise typer.BadParameter(
                "--limit cannot be combined with --apply-suggestions; filter by image or provider member",
                param_hint="--limit",
            )
        if summary_only or check:
            raise typer.BadParameter(
                "--apply-suggestions cannot be combined with --summary-only or --check",
                param_hint="--apply-suggestions",
            )
        result = matchlib.apply_naming_suggestions(
            selected_rows,
            match_root=match_root,
            name_map_path=name_map,
            repository_root=matchlib.REPO_ROOT,
        )
        if as_json:
            typer.echo(json.dumps(result, indent=2, sort_keys=True))
        else:
            typer.echo(
                " ".join(
                    (
                        f"applied={result['applied']}",
                        f"map_added={result['map_rows_added']}",
                        f"map_updated={result['map_rows_updated']}",
                        f"scope_updated={result['scope_dispositions_updated']}",
                        f"directories={result['directories_renamed']}",
                        f"references={result['config_references_updated']}",
                        f"aliases_removed={result['aliases_removed']}",
                    ),
                ),
            )
        return
    displayed_rows = selected_rows[:limit] if limit is not None else selected_rows
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "scope": scope,
                    "summary": matchlib.naming_debt_summary_payload(selected_rows),
                    "rows": (
                        []
                        if summary_only
                        else [matchlib.naming_debt_payload(row) for row in displayed_rows]
                    ),
                },
                indent=2,
                sort_keys=True,
            ),
        )
    elif summary_only:
        typer.echo(matchlib.render_naming_debt_summary(selected_rows))
    else:
        typer.echo(matchlib.render_naming_debt_table(displayed_rows))
    if check and selected_rows:
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
    sort_by: Literal["address", "fuzzy-gap", "size", "fuzzy", "unexplored"] = typer.Option(
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
    mode: Literal["auto", "recovery", "residual-audit"] = typer.Option(
        "auto",
        "--mode",
        help="queue defaults: auto fallback, broad recovery, or semantic-complete residual audit",
    ),
    scope: Literal["port", "all"] = typer.Option(
        matchlib.DEFAULT_MATCH_SCOPE,
        "--scope",
        help="matching ownership scope",
    ),
    jobs: int = typer.Option(matchlib.DEFAULT_MATCH_JOBS, "--jobs", "-j", min=1, help="parallel status jobs"),
    image: str | None = typer.Option(None, "--image", help="restrict targets to one image"),
    state: str | None = typer.Option(None, "--state", help="override comma-separated target states"),
    recovery: str | None = typer.Option(
        None,
        "--recovery",
        help="override comma-separated scratch recovery states; missing targets are always eligible",
    ),
    min_bytes: int = typer.Option(0, "--min-bytes", min=0, help="minimum native function bytes"),
    limit: int | None = typer.Option(None, "--limit", min=1, help="maximum targets to assign"),
    output_directory: Path | None = typer.Option(None, "--out", help="ignored plan/claim directory"),
    as_json: bool = typer.Option(False, "--json", help="emit the complete plan"),
) -> None:
    """Create deterministic, disjoint target claims for a worker batch."""
    requested_mode = mode
    effective_mode = "recovery" if mode == "auto" else mode
    default_state = "wip,audit" if effective_mode == "residual-audit" else "missing,wip"
    default_recovery = (
        "semantic-complete"
        if effective_mode == "residual-audit"
        else "incomplete,unspecified"
    )
    states = _parse_csv(state or default_state) or set()
    unknown_states = states - {"match", "audit", "wip", "error", "missing"}
    if unknown_states:
        raise typer.BadParameter(
            f"unknown states: {', '.join(sorted(unknown_states))}",
            param_hint="--state",
        )
    recoveries = _parse_csv(recovery or default_recovery) or set()
    allowed_recoveries = {"incomplete", "semantic-complete", "unspecified"}
    unknown_recoveries = recoveries - allowed_recoveries
    if unknown_recoveries:
        raise typer.BadParameter(
            f"unknown recovery states: {', '.join(sorted(unknown_recoveries))}",
            param_hint="--recovery",
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
    all_rows = matchlib.collect_triage_rows(
        statuses,
        images=(image,) if image is not None else None,
        scope=scope,
    )

    def selected_rows() -> list[matchlib.TriageRow]:
        return [
            row
            for row in all_rows
            if (
                row.state in states
                and row.target_size >= min_bytes
                and (
                    row.best_status is None
                    or matchlib.scratch_recovery(row.best_status) in recoveries
                )
            )
        ]

    rows = selected_rows()
    auto_fallback = False
    if not rows and requested_mode == "auto" and state is None and recovery is None:
        effective_mode = "residual-audit"
        states = {"audit", "wip"}
        recoveries = {"semantic-complete"}
        rows = selected_rows()
        auto_fallback = bool(rows)
    rows = matchlib.sort_triage_rows(rows, sort_by="fuzzy-gap")
    if limit is not None:
        rows = rows[:limit]
    if not rows:
        residual_targets = sum(
            row.state in {"wip", "audit"}
            and row.best_status is not None
            and matchlib.scratch_recovery(row.best_status) == "semantic-complete"
            for row in all_rows
        )
        suggested_command = "crimson match shard --mode residual-audit --workers <N>"
        message = f"no targets match the {effective_mode} shard filters"
        if effective_mode == "recovery" and residual_targets:
            message += (
                f"; {residual_targets} semantic-complete residual targets remain; "
                f"run `{suggested_command}`"
            )
        if as_json:
            typer.echo(
                json.dumps(
                    {
                        "error": "empty-shard",
                        "message": message,
                        "mode": effective_mode,
                        "requested_mode": requested_mode,
                        "semantic_complete_residual_targets": residual_targets,
                        "suggested_command": suggested_command if residual_targets else None,
                    },
                    indent=2,
                    sort_keys=True,
                ),
            )
        else:
            typer.echo(message, err=True)
        raise typer.Exit(code=1)
    plan = matchlib.build_match_shard_plan(
        rows,
        workers=workers,
        scope=scope,
        base_commit=_git_head(),
        match_root=match_root,
        filters={
            "image": image,
            "mode": effective_mode,
            "requested_mode": requested_mode,
            "auto_fallback": auto_fallback,
            "states": sorted(states),
            "recoveries": sorted(recoveries),
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
        f"mode={effective_mode} requested_mode={requested_mode} plan={plan_path}",
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
                object_extent=config.archive_extent,
                object_end_symbol=config.archive_end_symbol,
                object_size=config.archive_size,
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
            typer.echo(f"    object: {scratch['candidate_object']}")
            typer.echo(f"    dump: {scratch['commands']['dump']}")
    else:
        typer.echo("matcher: missing scratch")
    evidence = payload.get("mismatch_evidence")
    if evidence:
        cfg = evidence.get("cfg_alignment")
        if cfg:
            summary = cfg["summary"]
            typer.echo(
                "cfg: "
                f"blocks={summary['target_blocks']}/{summary['candidate_blocks']} "
                f"exact={summary['exact_pairs']} ambiguous={summary['exact_ambiguous_pairs']} "
                f"similar={summary['similar_pairs']} "
                f"unmatched={summary['unmatched_target']}/{summary['unmatched_candidate']} "
                f"edge-conflicts={summary['edge_conflicts']}",
            )
            residual_pairs = sorted(
                (
                    pair
                    for pair in cfg["pairs"]
                    if pair["kind"] != "exact" or pair["edge_consistent"] is False
                ),
                key=lambda pair: (
                    pair["edge_consistent"] is not False,
                    pair["kind"] == "exact-ambiguous",
                    pair["match_ratio"],
                    pair["target_block"],
                ),
            )
            for pair in residual_pairs[:12]:
                target_block = pair["target"]
                candidate_block = pair["candidate"]
                typer.echo(
                    f"  {pair['kind']} target=b{target_block['index']} "
                    f"0x{target_block['addresses']['start']:08x} "
                    f"candidate=b{candidate_block['index']} "
                    f"+0x{candidate_block['bytes']['start']:x} "
                    f"match={pair['match_ratio']:.1%} "
                    f"edges={pair['edge_consistent']}",
                )
        for index, region in enumerate(evidence["regions"], start=1):
            typer.echo(
                f"mismatch {index}: target={region['target_instructions']['start']}:"
                f"{region['target_instructions']['end']} "
                f"candidate={region['candidate_instructions']['start']}:"
                f"{region['candidate_instructions']['end']} "
                f"hints={','.join(region['hints'])}",
            )


@match_app.command("worker-outcome")
def cmd_match_worker_outcome(
    claim: Path = typer.Argument(..., help="worker claim JSON from `match shard`"),
    scratch: str = typer.Argument(..., help="claimed scratches/<directory>"),
    disposition: Literal["matched", "improved", "falsified", "blocked"] = typer.Option(
        ...,
        "--disposition",
        help="result of the residual-audit work",
    ),
    summary: str = typer.Option(..., "--summary", help="concise result and next-step summary"),
    hypothesis: list[str] | None = typer.Option(
        None,
        "--hypothesis",
        help="tested <kind>:<description>; repeat as needed",
    ),
    evidence: list[str] | None = typer.Option(
        None,
        "--evidence",
        help="evidence pointer or bounded negative result; repeat as needed",
    ),
    match_root: Path = typer.Option(matchlib.DEFAULT_MATCH_ROOT, "--match-root", help="tools/match root"),
    jobs: int = typer.Option(matchlib.DEFAULT_MATCH_JOBS, "--jobs", "-j", min=1, help="focused status jobs"),
    as_json: bool = typer.Option(False, "--json", help="emit the recorded outcome"),
) -> None:
    """Append a structured, batch-scoped outcome for one claimed target."""
    try:
        claim_payload = matchlib.load_match_claim(claim.resolve())
        if claim_payload.get("kind") != matchlib.WORKER_CLAIM_KIND:
            raise ValueError("worker-outcome requires a worker claim")
        batch_id = claim_payload.get("batch_id")
        if not isinstance(batch_id, str):
            raise TypeError("worker claim predates batch-scoped outcomes; create a new shard")
        claim_errors = matchlib.validate_match_claim(
            claim_payload,
            match_root=match_root,
            scope=str(claim_payload.get("scope", "")),
        )
        if claim_errors:
            raise ValueError("; ".join(claim_errors))
        scratch_path = Path(scratch)
        if scratch_path.is_absolute():
            scratch_path = scratch_path.resolve().relative_to(match_root.resolve())
        scratch_name = scratch_path.as_posix().removeprefix("./")
        targets = [
            target
            for _worker, target in matchlib.match_claim_targets(claim_payload)
            if target.get("scratch") == scratch_name
        ]
        if len(targets) != 1:
            raise ValueError(f"{scratch_name!r} is not one unique target in this worker claim")
        target = targets[0]
        directory = match_root / scratch_name
        config = matchlib.load_scratch_config(directory)
        statuses = matchlib.collect_scratch_statuses(
            match_root,
            jobs=jobs,
            scope=str(claim_payload["scope"]),
            directories=[directory],
        )
        if len(statuses) != 1:
            raise ValueError(f"{scratch_name} did not produce one status")
        status = statuses[0]
        if status.state == "error":
            raise ValueError(f"{scratch_name} evaluation failed: {status.error}")
        if disposition == "matched" and status.state != "match":
            raise ValueError("matched disposition requires an exact, reference-clean status")
        if disposition == "improved" and not matchlib.status_improves_claim_baseline(
            status,
            target.get("baseline"),
        ):
            raise ValueError("improved disposition does not beat the claim baseline")
        hypotheses = [
            matchlib.parse_worker_hypothesis(value)
            for value in hypothesis or []
        ]
        status_payload = matchlib.scratch_status_payload(status)
        status_payload["scratch"] = scratch_name
        outcome = {
            "schema": matchlib.SHARD_SCHEMA,
            "kind": matchlib.WORKER_OUTCOME_KIND,
            "recorded_at": datetime.now(UTC).isoformat(),
            "batch_id": batch_id,
            "base_commit": claim_payload["base_commit"],
            "worker": claim_payload["worker"],
            "scratch": scratch_name,
            "function": target["function"],
            "address": target["address"],
            "disposition": disposition,
            "summary": summary.strip(),
            "hypotheses": hypotheses,
            "evidence": [item.strip() for item in evidence or []],
            "baseline": target.get("baseline"),
            "status": status_payload,
        }
        output = matchlib.write_worker_outcome(config.directory, outcome)
    except Exception as exc:
        typer.echo(f"worker outcome failed: {str(exc).splitlines()[0]}", err=True)
        raise typer.Exit(code=2) from exc

    if as_json:
        typer.echo(json.dumps(outcome, indent=2, sort_keys=True))
    else:
        typer.echo(
            f"worker={outcome['worker']} scratch={scratch_name} "
            f"disposition={disposition} recorded={output}",
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
    require_outcome: bool = typer.Option(
        False,
        "--require-outcome",
        help="fail unless every target has a valid outcome for this batch",
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
        outcome_total = 0
        missing_outcomes = 0
        for _worker, target in matchlib.match_claim_targets(claim_payload):
            scratch = str(target["scratch"])
            status = statuses_by_directory.get(scratch)
            outcomes, outcome_errors = matchlib.worker_outcomes_for_target(
                claim_payload,
                target,
                match_root=match_root,
            )
            errors.extend(outcome_errors)
            outcome_total += len(outcomes)
            missing_outcomes += not bool(outcomes)
            targets.append(
                {
                    **target,
                    "handled": status is not None,
                    "outcome_count": len(outcomes),
                    "latest_outcome": outcomes[-1] if outcomes else None,
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
                "outcomes": outcome_total,
                "missing_outcomes": missing_outcomes,
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
            f"outcomes={outcome_total} missing_outcomes={missing_outcomes} "
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
    if require_outcome and missing_outcomes:
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
        except Exception as exc:  # noqa: BLE001 - report malformed claim batches without aborting status refresh
            claim_errors.append(str(exc).splitlines()[0])
    statuses = matchlib.collect_scratch_statuses(match_root, jobs=jobs, scope=scope)
    totals = matchlib.collect_image_totals(statuses, scope=scope)
    metadata_errors = matchlib.validate_scratch_status_metadata(statuses)
    experiment_paths = match_experiments.find_experiment_logs(match_root)
    experiment_payload = match_experiments.summarize_experiments(
        match_root,
        current_epochs=matchlib.scratch_experiment_epochs(
            match_root,
            directories=[path.parent for path in experiment_paths],
        ),
    )
    native_statuses = matchlib.collect_native_link_statuses(
        scope=scope,
        allow_absent_toolchain=True,
    )
    native_errors = [
        status
        for status in native_statuses
        if status.artifact_state != "current"
    ]
    write.parent.mkdir(parents=True, exist_ok=True)
    write.write_text(
        matchlib.render_status_markdown(
            statuses,
            totals,
            scope=scope,
            native_statuses=native_statuses,
        ),
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
        f"evaluation_errors={len(evaluation_errors)} "
        f"metadata_errors={len(metadata_errors)} "
        f"experiment_errors={len(experiment_payload['errors'])} "
        f"experiment_strict_errors={len(experiment_payload['strict_errors'])} "
        f"native_errors={len(native_errors)}",
    )
    for error in errors[:20]:
        typer.echo(f"  {error}", err=True)
    for error in claim_errors[:20]:
        typer.echo(f"  {error}", err=True)
    for error in metadata_errors[:20]:
        typer.echo(f"  {error}", err=True)
    for error in experiment_payload["errors"][:20]:
        typer.echo(f"  {error}", err=True)
    for error in experiment_payload["strict_errors"][:20]:
        typer.echo(f"  {error}", err=True)
    for status in native_errors:
        typer.echo(
            f"  {status.image}: {status.artifact_state}: {status.artifact_note}",
            err=True,
        )
    for diff_check in diff_checks:
        if diff_check.stdout:
            typer.echo(diff_check.stdout.rstrip(), err=True)
        if diff_check.stderr:
            typer.echo(diff_check.stderr.rstrip(), err=True)
    if (
        errors
        or claim_errors
        or evaluation_errors
        or metadata_errors
        or experiment_payload["errors"]
        or experiment_payload["strict_errors"]
        or native_errors
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
