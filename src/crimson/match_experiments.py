from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any, cast

EXPERIMENT_FILE = "experiments.jsonl"
EXPERIMENT_SCHEMA = 1
MUTATION_ERROR_AUDIT_KIND = "mutation-error-audit"
MUTATION_ERROR_AUDIT_CLASSIFICATION = "invalid-mutation-plan"
PROBE_ERROR_AUDIT_KIND = "probe-error-audit"
PROBE_ERROR_AUDIT_CLASSIFICATION = "invalid-probe-source"
EXPERIMENT_SORTS = frozenset(
    {
        "errors",
        "no-improvement",
        "records",
        "repeats",
        "scratch",
        "variants",
    },
)


def _experiment_kind(record: dict[str, Any]) -> str:
    kind = record.get("kind")
    if isinstance(kind, str) and kind:
        return kind
    if isinstance(record.get("baseline"), dict) and isinstance(record.get("probe"), dict):
        return "probe"
    return "unknown"


def _non_negative_int(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _number(value: object) -> float | None:
    if isinstance(value, int | float) and not isinstance(value, bool):
        return float(value)
    return None


def load_experiment_log(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{path}:{line_number}: invalid JSON: {exc.msg}")
            continue
        if not isinstance(record, dict):
            errors.append(f"{path}:{line_number}: experiment must be an object")
            continue
        records.append(record)
    return records, errors


def find_experiment_logs(
    match_root: Path,
    scratches: Collection[str] = (),
) -> list[Path]:
    root = match_root.resolve()
    if not scratches:
        return sorted(root.glob(f"scratches/*/{EXPERIMENT_FILE}"))

    paths: set[Path] = set()
    for value in scratches:
        supplied = Path(value)
        candidates = [supplied]
        if not supplied.is_absolute():
            candidates.extend((root / supplied, root / "scratches" / supplied))
        path = next((candidate.resolve() for candidate in candidates if candidate.exists()), None)
        if path is None:
            raise FileNotFoundError(f"scratch or experiment log not found: {value}")
        if path.is_dir():
            path /= EXPERIMENT_FILE
        if path.name != EXPERIMENT_FILE or not path.is_file():
            raise FileNotFoundError(f"experiment log not found: {path}")
        paths.add(path)
    return sorted(paths)


def _relative_scratch(path: Path, match_root: Path) -> str:
    try:
        return path.parent.resolve().relative_to(match_root.resolve()).as_posix()
    except ValueError:
        return str(path.parent.resolve())


def _first_mismatch_tradeoff(result: dict[str, Any]) -> bool:
    delta = result.get("delta")
    if not isinstance(delta, dict):
        return False
    first = delta.get("first_mismatch")
    if not isinstance(first, dict):
        return False
    baseline = _non_negative_int(first.get("baseline_target_offset"))
    probe = _non_negative_int(first.get("probe_target_offset"))
    return baseline is not None and probe is not None and probe < baseline


def _inferred_tradeoffs(
    result: dict[str, Any],
    baseline: dict[str, Any] | None,
) -> tuple[str, ...]:
    warnings: list[str] = []
    explicit = result.get("tradeoffs")
    if isinstance(explicit, list):
        explicit_strings = [item for item in explicit if isinstance(item, str)]
        if len(explicit_strings) == len(explicit):
            warnings.extend(explicit_strings)

    delta = result.get("delta")
    if not isinstance(delta, dict):
        return tuple(dict.fromkeys(warnings))
    fuzzy_delta = _number(delta.get("fuzzy_weighted_bytes"))
    if fuzzy_delta is None or fuzzy_delta < 0:
        return tuple(dict.fromkeys(warnings))

    references = delta.get("references")
    if isinstance(references, dict):
        unresolved = _number(references.get("unresolved")) or 0.0
        mismatch = _number(references.get("mismatch")) or 0.0
        if unresolved + mismatch > 0:
            warnings.append("reference-debt-increased")
        if (_number(references.get("ok")) or 0.0) < 0:
            warnings.append("resolved-references-decreased")
    if (_number(delta.get("prefix_instructions")) or 0.0) < 0:
        warnings.append("prefix-regressed")
    if _first_mismatch_tradeoff(result):
        warnings.append("first-mismatch-earlier")

    status = result.get("status")
    if isinstance(baseline, dict) and isinstance(status, dict):
        baseline_candidate = _non_negative_int(baseline.get("candidate_instructions"))
        baseline_target = _non_negative_int(baseline.get("target_instructions"))
        candidate = _non_negative_int(status.get("candidate_instructions"))
        target = _non_negative_int(status.get("target_instructions"))
        if (
            baseline_candidate is not None
            and baseline_target is not None
            and candidate is not None
            and target is not None
            and abs(candidate - target) > abs(baseline_candidate - baseline_target)
        ):
            warnings.append("instruction-count-further-from-target")
    return tuple(dict.fromkeys(warnings))


def _variant_key(result: dict[str, Any]) -> tuple[str, str, str] | None:
    source_sha256 = result.get("source_sha256")
    status = result.get("status")
    if not isinstance(source_sha256, str) or not source_sha256:
        return None
    compiler = str(status.get("compiler", "")) if isinstance(status, dict) else ""
    cflags = str(status.get("cflags", "")) if isinstance(status, dict) else ""
    return source_sha256, compiler, cflags


def _recorded_function(record: dict[str, Any]) -> tuple[str | None, str | None]:
    baseline = record.get("baseline")
    if not isinstance(baseline, dict):
        return None, None
    function = baseline.get("function")
    image = baseline.get("image")
    return (
        function if isinstance(function, str) else None,
        image if isinstance(image, str) else None,
    )


def _valid_epoch(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def mutation_error_evidence(record: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    results = record.get("results")
    if _experiment_kind(record) != "mutation-sweep" or not isinstance(results, list):
        return ()
    evidence: list[dict[str, Any]] = []
    for result_index, result in enumerate(results, start=1):
        if not isinstance(result, dict):
            continue
        status = result.get("status")
        if not isinstance(status, dict) or status.get("state") != "error":
            continue
        evidence.append(
            {
                "result": result_index,
                "label": result.get("label"),
                "source_sha256": result.get("source_sha256"),
                "error": status.get("error"),
            },
        )
    return tuple(evidence)


def mutation_error_evidence_sha256(record: dict[str, Any]) -> str:
    evidence = mutation_error_evidence(record)
    return hashlib.sha256(
        json.dumps(evidence, separators=(",", ":"), sort_keys=True).encode(),
    ).hexdigest()


def probe_error_evidence(record: dict[str, Any]) -> dict[str, Any] | None:
    probe = record.get("probe")
    if _experiment_kind(record) != "probe" or not isinstance(probe, dict):
        return None
    if probe.get("state") != "error":
        return None
    evidence = {
        "label": record.get("label"),
        "source_sha256": record.get("source_sha256"),
        "error": probe.get("error"),
    }
    source_tree_sha256 = record.get("source_tree_sha256")
    if source_tree_sha256 is not None:
        evidence["source_tree_sha256"] = source_tree_sha256
    return evidence


def probe_error_evidence_sha256(record: dict[str, Any]) -> str:
    evidence = probe_error_evidence(record)
    return hashlib.sha256(
        json.dumps(evidence, separators=(",", ":"), sort_keys=True).encode(),
    ).hexdigest()


def build_mutation_error_audit(
    path: Path,
    *,
    target_record: int,
    current_epoch: str,
    reason: str,
    recorded_at: str,
) -> dict[str, Any]:
    records, errors = load_experiment_log(path)
    if errors:
        raise ValueError(errors[0])
    if target_record < 1 or target_record > len(records):
        raise ValueError(f"{path}: target record {target_record} does not exist")
    target = records[target_record - 1]
    if _experiment_kind(target) != "mutation-sweep":
        raise ValueError(f"{path}:{target_record}: target is not a mutation sweep")
    evidence = mutation_error_evidence(target)
    if not evidence:
        raise ValueError(f"{path}:{target_record}: target has no errored variants")
    if target.get("baseline_epoch") != current_epoch:
        raise ValueError(f"{path}:{target_record}: target does not belong to the current baseline epoch")
    if not reason.strip():
        raise ValueError("mutation error audit requires a reason")
    if any(
        _experiment_kind(record) == MUTATION_ERROR_AUDIT_KIND
        and record.get("target_record") == target_record
        for record in records
    ):
        raise ValueError(f"{path}:{target_record}: mutation errors are already audited")
    return {
        "schema": EXPERIMENT_SCHEMA,
        "kind": MUTATION_ERROR_AUDIT_KIND,
        "recorded_at": recorded_at,
        "baseline_epoch": current_epoch,
        "target_record": target_record,
        "classification": MUTATION_ERROR_AUDIT_CLASSIFICATION,
        "errored_variants": len(evidence),
        "error_evidence_sha256": mutation_error_evidence_sha256(target),
        "reason": reason.strip(),
    }


def build_probe_error_audit(
    path: Path,
    *,
    target_record: int,
    current_epoch: str,
    reason: str,
    recorded_at: str,
) -> dict[str, Any]:
    records, errors = load_experiment_log(path)
    if errors:
        raise ValueError(errors[0])
    if target_record < 1 or target_record > len(records):
        raise ValueError(f"{path}: target record {target_record} does not exist")
    target = records[target_record - 1]
    if _experiment_kind(target) != "probe":
        raise ValueError(f"{path}:{target_record}: target is not a probe")
    if probe_error_evidence(target) is None:
        raise ValueError(f"{path}:{target_record}: target is not an errored probe")
    if target.get("baseline_epoch") != current_epoch:
        raise ValueError(f"{path}:{target_record}: target does not belong to the current baseline epoch")
    if not reason.strip():
        raise ValueError("probe error audit requires a reason")
    if any(
        _experiment_kind(record) == PROBE_ERROR_AUDIT_KIND
        and record.get("target_record") == target_record
        for record in records
    ):
        raise ValueError(f"{path}:{target_record}: probe error is already audited")
    return {
        "schema": EXPERIMENT_SCHEMA,
        "kind": PROBE_ERROR_AUDIT_KIND,
        "recorded_at": recorded_at,
        "baseline_epoch": current_epoch,
        "target_record": target_record,
        "classification": PROBE_ERROR_AUDIT_CLASSIFICATION,
        "error_evidence_sha256": probe_error_evidence_sha256(target),
        "reason": reason.strip(),
    }


def _validated_mutation_error_audits(
    records: list[dict[str, Any]],
    *,
    path: Path,
    errors: list[str],
) -> dict[int, dict[str, Any]]:
    audits: dict[int, dict[str, Any]] = {}
    for record_index, record in enumerate(records, start=1):
        if _experiment_kind(record) != MUTATION_ERROR_AUDIT_KIND:
            continue
        context = f"{path}:{record_index}"
        target_index = _non_negative_int(record.get("target_record"))
        if target_index is None or target_index < 1 or target_index >= record_index:
            errors.append(f"{context}: mutation error audit requires an earlier target_record")
            continue
        target = records[target_index - 1]
        if _experiment_kind(target) != "mutation-sweep":
            errors.append(f"{context}: audited target {target_index} is not a mutation sweep")
            continue
        evidence = mutation_error_evidence(target)
        if not evidence:
            errors.append(f"{context}: audited target {target_index} has no errored variants")
            continue
        if record.get("classification") != MUTATION_ERROR_AUDIT_CLASSIFICATION:
            errors.append(f"{context}: unsupported mutation error classification")
            continue
        if not isinstance(record.get("reason"), str) or not str(record["reason"]).strip():
            errors.append(f"{context}: mutation error audit requires a reason")
            continue
        if record.get("baseline_epoch") != target.get("baseline_epoch"):
            errors.append(f"{context}: mutation error audit epoch differs from its target")
            continue
        expected_digest = mutation_error_evidence_sha256(target)
        if record.get("error_evidence_sha256") != expected_digest:
            errors.append(f"{context}: mutation error evidence digest differs from its target")
            continue
        if record.get("errored_variants") != len(evidence):
            errors.append(f"{context}: audited errored_variants differs from its target")
            continue
        if target_index in audits:
            errors.append(f"{context}: duplicate audit for target record {target_index}")
            continue
        audits[target_index] = record
    return audits


def _validated_probe_error_audits(
    records: list[dict[str, Any]],
    *,
    path: Path,
    errors: list[str],
) -> dict[int, dict[str, Any]]:
    audits: dict[int, dict[str, Any]] = {}
    for record_index, record in enumerate(records, start=1):
        if _experiment_kind(record) != PROBE_ERROR_AUDIT_KIND:
            continue
        context = f"{path}:{record_index}"
        target_index = _non_negative_int(record.get("target_record"))
        if target_index is None or target_index < 1 or target_index >= record_index:
            errors.append(f"{context}: probe error audit requires an earlier target_record")
            continue
        target = records[target_index - 1]
        if _experiment_kind(target) != "probe":
            errors.append(f"{context}: audited target {target_index} is not a probe")
            continue
        if probe_error_evidence(target) is None:
            errors.append(f"{context}: audited target {target_index} is not an errored probe")
            continue
        if record.get("classification") != PROBE_ERROR_AUDIT_CLASSIFICATION:
            errors.append(f"{context}: unsupported probe error classification")
            continue
        if not isinstance(record.get("reason"), str) or not str(record["reason"]).strip():
            errors.append(f"{context}: probe error audit requires a reason")
            continue
        if record.get("baseline_epoch") != target.get("baseline_epoch"):
            errors.append(f"{context}: probe error audit epoch differs from its target")
            continue
        expected_digest = probe_error_evidence_sha256(target)
        if record.get("error_evidence_sha256") != expected_digest:
            errors.append(f"{context}: probe error evidence digest differs from its target")
            continue
        if target_index in audits:
            errors.append(f"{context}: duplicate audit for target record {target_index}")
            continue
        audits[target_index] = record
    return audits


def _non_improving_sweep_inconclusive_reasons(
    record: dict[str, Any],
    *,
    declared_variants: int | None,
    result_count: int,
    errored_variants: int,
    require_coverage: bool,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if errored_variants:
        reasons.append("variant-errors")

    possible = _non_negative_int(record.get("possible_variants"))
    never_evaluated = _non_negative_int(record.get("combinations_never_evaluated"))
    truncated = record.get("truncated")
    stop_reason = record.get("stop_reason")
    has_coverage = possible is not None and never_evaluated is not None and isinstance(truncated, bool)
    if not has_coverage:
        if require_coverage:
            reasons.append("coverage-unrecorded")
        return tuple(reasons)
    if (
        truncated
        or declared_variants != possible
        or result_count != possible
        or never_evaluated
        or stop_reason is not None
    ):
        reasons.append("incomplete-coverage")
    return tuple(dict.fromkeys(reasons))


def summarize_experiment_log(
    path: Path,
    *,
    match_root: Path,
    current_epoch: str | None = None,
    classify_epochs: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    records, errors = load_experiment_log(path)
    mutation_error_audits = _validated_mutation_error_audits(
        records,
        path=path,
        errors=errors,
    )
    probe_error_audits = _validated_probe_error_audits(
        records,
        path=path,
        errors=errors,
    )
    kinds: Counter[str] = Counter()
    current_kinds: Counter[str] = Counter()
    mutation_improvements: list[bool] = []
    current_mutation_outcomes: list[bool | None] = []
    spec_shas: Counter[str] = Counter()
    variant_keys: Counter[tuple[str, str, str]] = Counter()
    strict_errors: list[str] = []
    latest_recorded_at: str | None = None
    function: str | None = None
    image: str | None = None
    current_records = 0
    historical_records = 0
    unversioned_records = 0
    evaluated_variants = 0
    improving_variants = 0
    neutral_variants = 0
    degrading_variants = 0
    errored_variants = 0
    tradeoff_variants = 0
    improving_sweeps = 0
    improving_probes = 0
    exact_winners = 0
    current_inconclusive_sweeps = 0
    current_errored_variants = 0
    audited_errored_variants = 0
    audited_probe_errors = 0

    for record_index, record in enumerate(records, start=1):
        context = f"{path}:{record_index}"
        schema = record.get("schema")
        if schema is not None and schema != EXPERIMENT_SCHEMA:
            errors.append(f"{context}: unsupported experiment schema {schema!r}")
        kind = _experiment_kind(record)
        kinds[kind] += 1
        baseline_epoch = record.get("baseline_epoch")
        if baseline_epoch is None:
            unversioned_records += 1
        elif not _valid_epoch(baseline_epoch):
            errors.append(f"{context}: baseline_epoch must be a lowercase SHA-256 digest")
        is_current = not classify_epochs or (
            current_epoch is not None and baseline_epoch == current_epoch
        )
        if is_current:
            current_records += 1
            current_kinds[kind] += 1
        else:
            historical_records += 1
        recorded_at = record.get("recorded_at")
        if isinstance(recorded_at, str) and (latest_recorded_at is None or recorded_at > latest_recorded_at):
            latest_recorded_at = recorded_at
        recorded_function, recorded_image = _recorded_function(record)
        function = recorded_function or function
        image = recorded_image or image

        if kind == "mutation-sweep":
            results = record.get("results")
            if not isinstance(results, list):
                errors.append(f"{context}: mutation-sweep results must be an array")
                continue
            declared = _non_negative_int(record.get("evaluated_variants"))
            if declared is None:
                errors.append(f"{context}: mutation-sweep evaluated_variants must be non-negative")
            elif declared != len(results):
                errors.append(
                    f"{context}: evaluated_variants={declared} does not match {len(results)} recorded results",
                )
            spec_sha = record.get("spec_sha256")
            if isinstance(spec_sha, str) and spec_sha:
                spec_shas[spec_sha] += 1
            raw_best_improves = record.get("best_improves")
            if not isinstance(raw_best_improves, bool):
                errors.append(f"{context}: mutation-sweep best_improves must be boolean")
            best_improves = raw_best_improves is True
            mutation_improvements.append(best_improves)
            improving_sweeps += best_improves
            winner = record.get("winner")
            if best_improves and not isinstance(winner, dict):
                errors.append(f"{context}: improving mutation-sweep requires a winner")
            elif not best_improves and winner is not None:
                errors.append(f"{context}: non-improving mutation-sweep cannot have a winner")
            if (
                isinstance(winner, dict)
                and isinstance(winner.get("status"), dict)
                and winner["status"].get("state") == "match"
            ):
                exact_winners += 1

            baseline = record.get("baseline")
            baseline_status = cast(dict[str, Any], baseline) if isinstance(baseline, dict) else None
            record_errored_variants = 0
            for result_index, result in enumerate(results, start=1):
                if not isinstance(result, dict):
                    errors.append(f"{context}: result {result_index} must be an object")
                    continue
                typed_result = cast(dict[str, Any], result)
                evaluated_variants += 1
                key = _variant_key(typed_result)
                if key is None:
                    errors.append(f"{context}: result {result_index} requires source_sha256")
                else:
                    variant_keys[key] += 1
                status = typed_result.get("status")
                variant_errored = isinstance(status, dict) and status.get("state") == "error"
                if variant_errored:
                    errored_variants += 1
                    record_errored_variants += 1
                delta = typed_result.get("delta")
                fuzzy_delta = _number(delta.get("fuzzy_weighted_bytes")) if isinstance(delta, dict) else None
                if fuzzy_delta is None:
                    errors.append(
                        f"{context}: result {result_index} requires a fuzzy byte delta",
                    )
                elif variant_errored:
                    pass
                elif fuzzy_delta > 0:
                    improving_variants += 1
                elif fuzzy_delta == 0:
                    neutral_variants += 1
                else:
                    degrading_variants += 1
                if not variant_errored:
                    tradeoff_variants += bool(
                        _inferred_tradeoffs(typed_result, baseline_status),
                    )
            if is_current:
                errors_audited = record_index in mutation_error_audits
                if errors_audited:
                    audited_errored_variants += record_errored_variants
                else:
                    current_errored_variants += record_errored_variants
                if best_improves:
                    current_mutation_outcomes.append(True)
                    inconclusive_reasons = (
                        ("variant-errors",) if record_errored_variants else ()
                    )
                else:
                    inconclusive_reasons = _non_improving_sweep_inconclusive_reasons(
                        record,
                        declared_variants=declared,
                        result_count=len(results),
                        errored_variants=record_errored_variants,
                        require_coverage=classify_epochs,
                    )
                    current_mutation_outcomes.append(
                        None if inconclusive_reasons else False,
                    )
                if inconclusive_reasons:
                    current_inconclusive_sweeps += 1
                if record_errored_variants and not errors_audited:
                    strict_errors.append(
                        f"{context}: current mutation sweep has "
                        f"{record_errored_variants} errored variants",
                    )
                if isinstance(baseline_status, dict) and baseline_status.get("state") == "error":
                    strict_errors.append(f"{context}: current mutation baseline is an error")
        elif kind == "probe":
            delta = record.get("delta")
            fuzzy_delta = _number(delta.get("fuzzy_weighted_bytes")) if isinstance(delta, dict) else None
            improving_probes += fuzzy_delta is not None and fuzzy_delta > 0
            if is_current:
                baseline = record.get("baseline")
                probe = record.get("probe")
                if isinstance(baseline, dict) and baseline.get("state") == "error":
                    strict_errors.append(f"{context}: current probe baseline is an error")
                if isinstance(probe, dict) and probe.get("state") == "error":
                    if record_index in probe_error_audits:
                        audited_probe_errors += 1
                    else:
                        strict_errors.append(f"{context}: current probe result is an error")

    no_improvement_streak = 0
    for outcome in reversed(current_mutation_outcomes):
        if outcome is not False:
            break
        no_improvement_streak += 1
    repeated_variants = sum(count - 1 for count in variant_keys.values())
    repeated_spec_runs = sum(count - 1 for count in spec_shas.values())
    flags: list[str] = []
    if repeated_variants:
        flags.append("repeated-variants")
    if repeated_spec_runs:
        flags.append("repeated-specs")
    if no_improvement_streak >= 3:
        flags.append("stalled")
    if tradeoff_variants:
        flags.append("metric-tradeoffs")
    if errored_variants:
        flags.append("variant-errors")
    if audited_errored_variants:
        flags.append("audited-plan-errors")
    if audited_probe_errors:
        flags.append("audited-probe-errors")
    if current_inconclusive_sweeps:
        flags.append("inconclusive-sweeps")
    if classify_epochs and records and not current_records:
        flags.append("historical-only")
    if errors:
        flags.append("malformed")

    return (
        {
            "scratch": _relative_scratch(path, match_root),
            "function": function,
            "image": image,
            "current_epoch": current_epoch if classify_epochs else None,
            "records": len(records),
            "current_records": current_records,
            "historical_records": historical_records,
            "unversioned_records": unversioned_records,
            "kinds": dict(sorted(kinds.items())),
            "current_kinds": dict(sorted(current_kinds.items())),
            "mutation_sweeps": kinds["mutation-sweep"],
            "probes": kinds["probe"],
            "evaluated_variants": evaluated_variants,
            "unique_variants": len(variant_keys),
            "repeated_variants": repeated_variants,
            "improving_variants": improving_variants,
            "neutral_variants": neutral_variants,
            "degrading_variants": degrading_variants,
            "errored_variants": errored_variants,
            "tradeoff_variants": tradeoff_variants,
            "improving_sweeps": improving_sweeps,
            "improving_probes": improving_probes,
            "exact_winners": exact_winners,
            "no_improvement_sweeps": len(mutation_improvements) - improving_sweeps,
            "no_improvement_streak": no_improvement_streak,
            "current_inconclusive_sweeps": current_inconclusive_sweeps,
            "current_errored_variants": current_errored_variants,
            "audited_errored_variants": audited_errored_variants,
            "mutation_error_audits": len(mutation_error_audits),
            "audited_probe_errors": audited_probe_errors,
            "probe_error_audits": len(probe_error_audits),
            "unique_specs": len(spec_shas),
            "repeated_spec_runs": repeated_spec_runs,
            "latest_recorded_at": latest_recorded_at,
            "flags": flags,
            "errors": len(errors),
            "strict_errors": len(strict_errors),
        },
        [*errors, *strict_errors],
    )


def sort_experiment_rows(
    rows: list[dict[str, Any]],
    *,
    sort_by: str,
) -> list[dict[str, Any]]:
    if sort_by not in EXPERIMENT_SORTS:
        raise ValueError(f"unknown experiment sort {sort_by!r}")
    if sort_by == "scratch":
        return sorted(rows, key=lambda row: str(row["scratch"]))
    fields = {
        "errors": ("errored_variants", "evaluated_variants"),
        "no-improvement": ("no_improvement_streak", "no_improvement_sweeps"),
        "records": ("records", "evaluated_variants"),
        "repeats": ("repeated_variants", "repeated_spec_runs"),
        "variants": ("evaluated_variants", "records"),
    }[sort_by]
    return sorted(
        rows,
        key=lambda row: (
            *(int(row[field]) for field in fields),
            str(row["scratch"]),
        ),
        reverse=True,
    )


def summarize_experiments(
    match_root: Path,
    *,
    scratches: Collection[str] = (),
    sort_by: str = "variants",
    current_epochs: Mapping[Path, str] | None = None,
) -> dict[str, Any]:
    paths = find_experiment_logs(match_root, scratches)
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    strict_errors: list[str] = []
    for path in paths:
        row, row_issues = summarize_experiment_log(
            path,
            match_root=match_root,
            current_epoch=(
                current_epochs.get(path.parent.resolve())
                if current_epochs is not None
                else None
            ),
            classify_epochs=current_epochs is not None,
        )
        rows.append(row)
        structural_count = int(row["errors"])
        errors.extend(row_issues[:structural_count])
        strict_errors.extend(row_issues[structural_count:])
    rows = sort_experiment_rows(rows, sort_by=sort_by)
    kinds: Counter[str] = Counter()
    for row in rows:
        kinds.update(row["kinds"])
    return {
        "schema": EXPERIMENT_SCHEMA,
        "kind": "crimson-match-experiment-summary",
        "sort": sort_by,
        "summary": {
            "files": len(paths),
            "records": sum(int(row["records"]) for row in rows),
            "current_records": sum(int(row["current_records"]) for row in rows),
            "historical_records": sum(int(row["historical_records"]) for row in rows),
            "unversioned_records": sum(int(row["unversioned_records"]) for row in rows),
            "kinds": dict(sorted(kinds.items())),
            "evaluated_variants": sum(int(row["evaluated_variants"]) for row in rows),
            "unique_variants": sum(int(row["unique_variants"]) for row in rows),
            "repeated_variants": sum(int(row["repeated_variants"]) for row in rows),
            "improving_variants": sum(int(row["improving_variants"]) for row in rows),
            "neutral_variants": sum(int(row["neutral_variants"]) for row in rows),
            "degrading_variants": sum(int(row["degrading_variants"]) for row in rows),
            "errored_variants": sum(int(row["errored_variants"]) for row in rows),
            "tradeoff_variants": sum(int(row["tradeoff_variants"]) for row in rows),
            "improving_sweeps": sum(int(row["improving_sweeps"]) for row in rows),
            "improving_probes": sum(int(row["improving_probes"]) for row in rows),
            "exact_winners": sum(int(row["exact_winners"]) for row in rows),
            "stalled_scratches": sum("stalled" in row["flags"] for row in rows),
            "current_inconclusive_sweeps": sum(
                int(row["current_inconclusive_sweeps"]) for row in rows
            ),
            "current_errored_variants": sum(
                int(row["current_errored_variants"]) for row in rows
            ),
            "audited_errored_variants": sum(
                int(row["audited_errored_variants"]) for row in rows
            ),
            "mutation_error_audits": sum(
                int(row["mutation_error_audits"]) for row in rows
            ),
            "audited_probe_errors": sum(
                int(row["audited_probe_errors"]) for row in rows
            ),
            "probe_error_audits": sum(
                int(row["probe_error_audits"]) for row in rows
            ),
            "errors": len(errors),
            "strict_errors": len(strict_errors),
        },
        "errors": errors,
        "strict_errors": strict_errors,
        "rows": rows,
    }


def render_experiment_summary(payload: dict[str, Any]) -> str:
    rows: list[tuple[str, ...]] = [
        (
            "scratch",
            "current/all",
            "sweeps",
            "probes",
            "variants",
            "better/same/worse/error",
            "repeats",
            "wins",
            "exact",
            "streak",
            "flags",
        ),
    ]
    for row in payload["rows"]:
        rows.append(
            (
                str(row["scratch"]).removeprefix("scratches/"),
                f"{row['current_records']}/{row['records']}",
                str(row["mutation_sweeps"]),
                str(row["probes"]),
                str(row["evaluated_variants"]),
                (
                    f"{row['improving_variants']}/{row['neutral_variants']}/"
                    f"{row['degrading_variants']}/{row['errored_variants']}"
                ),
                str(row["repeated_variants"]),
                str(row["improving_sweeps"]),
                str(row["exact_winners"]),
                str(row["no_improvement_streak"]),
                ",".join(row["flags"]) or "-",
            ),
        )
    widths = [max(len(row[column]) for row in rows) for column in range(len(rows[0]))]
    lines = ["  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip() for row in rows]
    summary = payload["summary"]
    lines.append(
        (
            f"\nfiles={summary['files']} records={summary['records']} "
            f"current/historical/unversioned={summary['current_records']}/"
            f"{summary['historical_records']}/{summary['unversioned_records']} "
            f"kinds="
            + "/".join(f"{kind}:{count}" for kind, count in summary["kinds"].items())
            + f"; variants={summary['evaluated_variants']} "
            f"unique={summary['unique_variants']} repeats={summary['repeated_variants']} "
            f"better/same/worse/error={summary['improving_variants']}/"
            f"{summary['neutral_variants']}/{summary['degrading_variants']}/"
            f"{summary['errored_variants']} "
            f"tradeoffs={summary['tradeoff_variants']} "
            f"sweep-wins={summary['improving_sweeps']} exact={summary['exact_winners']} "
            f"stalled={summary['stalled_scratches']} "
            f"inconclusive={summary['current_inconclusive_sweeps']} "
            f"audited-plan-errors={summary['mutation_error_audits']}/"
            f"{summary['audited_errored_variants']} "
            f"audited-probe-errors={summary['probe_error_audits']}/"
            f"{summary['audited_probe_errors']} "
            f"errors={summary['errors']} strict-errors={summary['strict_errors']}"
        ),
    )
    return "\n".join(lines)
