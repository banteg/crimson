from __future__ import annotations

import hashlib
import itertools
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from . import match as matchlib

MUTATION_SPEC_SCHEMA = 1


@dataclass(frozen=True, slots=True)
class MutationReplacement:
    name: str
    text: str


@dataclass(frozen=True, slots=True)
class MutationSite:
    name: str
    find: str
    replacements: tuple[MutationReplacement, ...]
    occurrence: int | None = None


@dataclass(frozen=True, slots=True)
class MutationSpec:
    sites: tuple[MutationSite, ...]
    sha256: str


@dataclass(frozen=True, slots=True)
class MutationChoice:
    site: str
    replacement: str
    replacement_index: int


@dataclass(frozen=True, slots=True)
class MutationVariant:
    label: str
    source_text: str
    source_sha256: str
    choices: tuple[MutationChoice, ...]


@dataclass(frozen=True, slots=True)
class MutationBatch:
    variants: tuple[MutationVariant, ...]
    possible_by_changes: tuple[int, ...]

    @property
    def possible_variants(self) -> int:
        return sum(self.possible_by_changes)

    @property
    def planned_by_changes(self) -> tuple[int, ...]:
        return _variant_counts_by_changes(self.variants, len(self.possible_by_changes))

    @property
    def truncated(self) -> bool:
        return len(self.variants) < self.possible_variants


@dataclass(frozen=True, slots=True)
class MutationEvaluation:
    variant: MutationVariant
    status: matchlib.ScratchStatus
    baseline: matchlib.ScratchStatus

    @property
    def fuzzy_delta_bytes(self) -> float:
        return self.status.fuzzy_weighted_bytes - self.baseline.fuzzy_weighted_bytes

    @property
    def ratio_delta(self) -> float | None:
        if self.status.ratio is None or self.baseline.ratio is None:
            return None
        return self.status.ratio - self.baseline.ratio

    @property
    def tradeoffs(self) -> tuple[str, ...]:
        return matchlib.fuzzy_score_tradeoffs(self.baseline, self.status)


@dataclass(frozen=True, slots=True)
class MutationSweep:
    spec: MutationSpec
    baseline: matchlib.ScratchStatus
    evaluations: tuple[MutationEvaluation, ...]
    possible_by_changes: tuple[int, ...]
    planned_by_changes: tuple[int, ...]
    stop_reason: str | None = None

    @property
    def possible_variants(self) -> int:
        return sum(self.possible_by_changes)

    @property
    def planned_variants(self) -> int:
        return sum(self.planned_by_changes)

    @property
    def evaluated_by_changes(self) -> tuple[int, ...]:
        counts = [0] * len(self.possible_by_changes)
        for evaluation in self.evaluations:
            counts[len(evaluation.variant.choices) - 1] += 1
        return tuple(counts)

    @property
    def unevaluated_interactions(self) -> int:
        return sum(self.possible_by_changes[1:]) - sum(self.evaluated_by_changes[1:])

    @property
    def truncated(self) -> bool:
        return len(self.evaluations) < self.possible_variants

    @property
    def best(self) -> MutationEvaluation | None:
        return self.evaluations[0] if self.evaluations else None

    @property
    def best_improves(self) -> bool:
        return self.best is not None and _status_rank(self.best.status) > _status_rank(self.baseline)


@dataclass(frozen=True, slots=True)
class _ResolvedSite:
    site: MutationSite
    start: int
    end: int


def _required_string(value: object, *, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} must be a non-empty string")
    return value


def _parse_replacement(value: object, *, site_name: str, index: int) -> MutationReplacement:
    if isinstance(value, str):
        return MutationReplacement(name=f"alt-{index}", text=value)
    if not isinstance(value, dict):
        raise TypeError(f"site {site_name!r} replacement {index} must be a string or object")
    text = value.get("text")
    if not isinstance(text, str):
        raise TypeError(f"site {site_name!r} replacement {index} text must be a string")
    return MutationReplacement(
        name=_required_string(value.get("name"), context=f"site {site_name!r} replacement {index} name"),
        text=text,
    )


def load_mutation_spec(path: Path) -> MutationSpec:
    raw = path.read_bytes()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise TypeError(f"{path}: mutation spec must be an object")
    if payload.get("schema") != MUTATION_SPEC_SCHEMA:
        raise ValueError(f"{path}: mutation spec schema must be {MUTATION_SPEC_SCHEMA}")
    raw_sites = payload.get("sites")
    if not isinstance(raw_sites, list) or not raw_sites:
        raise ValueError(f"{path}: sites must be a non-empty array")

    sites: list[MutationSite] = []
    seen_names: set[str] = set()
    for site_index, value in enumerate(raw_sites, start=1):
        if not isinstance(value, dict):
            raise TypeError(f"{path}: site {site_index} must be an object")
        name = _required_string(value.get("name"), context=f"site {site_index} name")
        if name in seen_names:
            raise ValueError(f"{path}: duplicate site name {name!r}")
        seen_names.add(name)
        find = _required_string(value.get("find"), context=f"site {name!r} find")
        raw_replacements = value.get("replacements")
        if not isinstance(raw_replacements, list) or not raw_replacements:
            raise ValueError(f"{path}: site {name!r} replacements must be a non-empty array")
        replacements = tuple(
            _parse_replacement(item, site_name=name, index=index)
            for index, item in enumerate(raw_replacements, start=1)
        )
        replacement_names = [replacement.name for replacement in replacements]
        replacement_texts = [replacement.text for replacement in replacements]
        if len(replacement_names) != len(set(replacement_names)):
            raise ValueError(f"{path}: site {name!r} has duplicate replacement names")
        if len(replacement_texts) != len(set(replacement_texts)):
            raise ValueError(f"{path}: site {name!r} has duplicate replacement text")
        if find in replacement_texts:
            raise ValueError(f"{path}: site {name!r} includes its unchanged find text as a replacement")
        raw_occurrence = value.get("occurrence")
        if raw_occurrence is not None and (
            not isinstance(raw_occurrence, int) or isinstance(raw_occurrence, bool) or raw_occurrence < 1
        ):
            raise ValueError(f"{path}: site {name!r} occurrence must be a positive integer")
        sites.append(
            MutationSite(
                name=name,
                find=find,
                replacements=replacements,
                occurrence=raw_occurrence,
            ),
        )
    return MutationSpec(sites=tuple(sites), sha256=hashlib.sha256(raw).hexdigest())


def _resolve_site(source_text: str, site: MutationSite) -> _ResolvedSite:
    offsets: list[int] = []
    start = 0
    while (offset := source_text.find(site.find, start)) != -1:
        offsets.append(offset)
        start = offset + max(1, len(site.find))
    if site.occurrence is None:
        if len(offsets) != 1:
            raise ValueError(
                f"mutation site {site.name!r} must match exactly once; found {len(offsets)} "
                "(set occurrence to select one)",
            )
        offset = offsets[0]
    else:
        if site.occurrence > len(offsets):
            raise ValueError(
                f"mutation site {site.name!r} occurrence {site.occurrence} not found; "
                f"only {len(offsets)} matches",
            )
        offset = offsets[site.occurrence - 1]
    return _ResolvedSite(site=site, start=offset, end=offset + len(site.find))


def _resolve_sites(source_text: str, spec: MutationSpec) -> tuple[_ResolvedSite, ...]:
    resolved = tuple(_resolve_site(source_text, site) for site in spec.sites)
    ordered = sorted(resolved, key=lambda site: (site.start, site.end))
    for left, right in itertools.pairwise(ordered):
        if right.start < left.end:
            raise ValueError(f"mutation sites {left.site.name!r} and {right.site.name!r} overlap")
    return resolved


def _possible_variant_counts(sites: tuple[_ResolvedSite, ...], max_changes: int) -> tuple[int, ...]:
    counts = [0] * (max_changes + 1)
    counts[0] = 1
    for site in sites:
        alternatives = len(site.site.replacements)
        for changes in range(max_changes, 0, -1):
            counts[changes] += counts[changes - 1] * alternatives
    return tuple(counts[1:])


def _variant_counts_by_changes(
    variants: tuple[MutationVariant, ...],
    max_changes: int,
) -> tuple[int, ...]:
    counts = [0] * max_changes
    for variant in variants:
        counts[len(variant.choices) - 1] += 1
    return tuple(counts)


def generate_mutation_variants(
    source_text: str,
    spec: MutationSpec,
    *,
    max_changes: int = 1,
    max_variants: int = 256,
) -> MutationBatch:
    if max_changes < 1:
        raise ValueError("max_changes must be at least 1")
    if max_variants < 1:
        raise ValueError("max_variants must be at least 1")
    resolved = _resolve_sites(source_text, spec)
    max_changes = min(max_changes, len(resolved))
    possible_by_changes = _possible_variant_counts(resolved, max_changes)
    variants: list[MutationVariant] = []

    for change_count in range(1, max_changes + 1):
        for selected_sites in itertools.combinations(resolved, change_count):
            alternatives = [range(len(site.site.replacements)) for site in selected_sites]
            for replacement_indices in itertools.product(*alternatives):
                edits: list[tuple[int, int, str]] = []
                choices: list[MutationChoice] = []
                for site, replacement_index in zip(selected_sites, replacement_indices, strict=True):
                    replacement = site.site.replacements[replacement_index]
                    edits.append((site.start, site.end, replacement.text))
                    choices.append(
                        MutationChoice(
                            site=site.site.name,
                            replacement=replacement.name,
                            replacement_index=replacement_index + 1,
                        ),
                    )
                mutated = source_text
                for start, end, replacement_text in sorted(edits, reverse=True):
                    mutated = f"{mutated[:start]}{replacement_text}{mutated[end:]}"
                label = "+".join(f"{choice.site}/{choice.replacement}" for choice in choices)
                variants.append(
                    MutationVariant(
                        label=label,
                        source_text=mutated,
                        source_sha256=hashlib.sha256(mutated.encode()).hexdigest(),
                        choices=tuple(choices),
                    ),
                )
                if len(variants) == max_variants:
                    return MutationBatch(
                        variants=tuple(variants),
                        possible_by_changes=possible_by_changes,
                    )
    return MutationBatch(
        variants=tuple(variants),
        possible_by_changes=possible_by_changes,
    )


def _status_rank(status: matchlib.ScratchStatus) -> tuple[int, float, int, int, int]:
    state_rank = {"error": 0, "wip": 1, "audit": 2, "match": 3}[status.state]
    return (
        state_rank,
        status.ratio if status.ratio is not None else -1.0,
        -(status.masked_unresolved + status.masked_mismatches),
        status.prefix_instructions,
        -abs(status.candidate_instructions - status.target_instructions),
    )


def _evaluation_rank(evaluation: MutationEvaluation) -> tuple[tuple[int, float, int, int, int], int, str]:
    return (_status_rank(evaluation.status), -len(evaluation.variant.choices), evaluation.variant.label)


def evaluate_mutation_sweep(
    config: matchlib.ScratchConfig,
    spec: MutationSpec,
    *,
    source_text: str,
    source_path: Path | None = None,
    match_root: Path = matchlib.DEFAULT_MATCH_ROOT,
    compiler: str | None = None,
    cflags: str | None = None,
    max_changes: int = 1,
    max_variants: int = 256,
    jobs: int = matchlib.DEFAULT_MATCH_JOBS,
    stop_on_improvement: bool = False,
    time_budget: float | None = None,
) -> MutationSweep:
    if jobs < 1:
        raise ValueError("jobs must be at least 1")
    if time_budget is not None and time_budget <= 0:
        raise ValueError("time_budget must be positive")
    profile = replace(
        config,
        compiler=compiler or config.compiler,
        cflags=cflags or config.cflags,
    )
    baseline = matchlib.evaluate_scratch(profile, match_root)
    batch = generate_mutation_variants(
        source_text,
        spec,
        max_changes=max_changes,
        max_variants=max_variants,
    )

    def evaluate(variant: MutationVariant) -> MutationEvaluation:
        status = matchlib.evaluate_source_overlay(
            profile,
            variant.source_text,
            match_root=match_root,
            source_path=source_path,
        )
        return MutationEvaluation(variant=variant, status=status, baseline=baseline)

    evaluations: list[MutationEvaluation] = []
    stop_reason: str | None = None
    started_at = time.monotonic()
    for offset in range(0, len(batch.variants), jobs):
        if time_budget is not None and time.monotonic() - started_at >= time_budget:
            stop_reason = "time-budget"
            break
        variants = batch.variants[offset : offset + jobs]
        if len(variants) == 1:
            completed = [evaluate(variants[0])]
        else:
            with ThreadPoolExecutor(max_workers=len(variants)) as executor:
                completed = list(executor.map(evaluate, variants))
        evaluations.extend(completed)
        if stop_on_improvement and any(_status_rank(result.status) > _status_rank(baseline) for result in completed):
            stop_reason = "improvement"
            break
    if stop_reason is None and batch.truncated:
        stop_reason = "variant-budget"
    evaluations.sort(key=_evaluation_rank, reverse=True)
    return MutationSweep(
        spec=spec,
        baseline=baseline,
        evaluations=tuple(evaluations),
        possible_by_changes=batch.possible_by_changes,
        planned_by_changes=batch.planned_by_changes,
        stop_reason=stop_reason,
    )


def mutation_evaluation_payload(evaluation: MutationEvaluation) -> dict[str, Any]:
    status = matchlib.scratch_status_payload(evaluation.status)
    status["scratch"] = "<shadow>"
    return {
        "label": evaluation.variant.label,
        "source_sha256": evaluation.variant.source_sha256,
        "tradeoffs": list(evaluation.tradeoffs),
        "mutations": [
            {
                "site": choice.site,
                "replacement": choice.replacement,
                "replacement_index": choice.replacement_index,
            }
            for choice in evaluation.variant.choices
        ],
        "status": status,
        "delta": {
            "match_ratio": evaluation.ratio_delta,
            "fuzzy_weighted_bytes": evaluation.fuzzy_delta_bytes,
            "candidate_instructions": (
                evaluation.status.candidate_instructions - evaluation.baseline.candidate_instructions
            ),
            "prefix_instructions": (
                evaluation.status.prefix_instructions - evaluation.baseline.prefix_instructions
            ),
            "first_mismatch": {
                "baseline_target_offset": evaluation.baseline.first_target_mismatch_offset,
                "probe_target_offset": evaluation.status.first_target_mismatch_offset,
                "baseline_candidate_offset": evaluation.baseline.first_candidate_mismatch_offset,
                "probe_candidate_offset": evaluation.status.first_candidate_mismatch_offset,
            },
            "references": {
                "ok": evaluation.status.masked_ok - evaluation.baseline.masked_ok,
                "unresolved": evaluation.status.masked_unresolved - evaluation.baseline.masked_unresolved,
                "mismatch": evaluation.status.masked_mismatches - evaluation.baseline.masked_mismatches,
            },
        },
    }


def mutation_sweep_payload(sweep: MutationSweep, *, limit: int | None = None) -> dict[str, Any]:
    evaluations = sweep.evaluations if limit is None else sweep.evaluations[:limit]
    winner = (
        mutation_evaluation_payload(sweep.best)
        if sweep.best is not None and sweep.best_improves
        else None
    )
    return {
        "schema": MUTATION_SPEC_SCHEMA,
        "spec_sha256": sweep.spec.sha256,
        "possible_variants": sweep.possible_variants,
        "planned_variants": sweep.planned_variants,
        "evaluated_variants": len(sweep.evaluations),
        "coverage_by_changes": [
            {
                "changes": changes,
                "possible": possible,
                "planned": planned,
                "evaluated": evaluated,
                "never_evaluated": possible - evaluated,
            }
            for changes, (possible, planned, evaluated) in enumerate(
                zip(
                    sweep.possible_by_changes,
                    sweep.planned_by_changes,
                    sweep.evaluated_by_changes,
                    strict=True,
                ),
                start=1,
            )
        ],
        "combinations_never_evaluated": sweep.unevaluated_interactions,
        "truncated": sweep.truncated,
        "stop_reason": sweep.stop_reason,
        "best_improves": sweep.best_improves,
        "best_tradeoffs": list(sweep.best.tradeoffs) if sweep.best is not None else [],
        "tradeoff_variants": sum(bool(evaluation.tradeoffs) for evaluation in sweep.evaluations),
        "winner": winner,
        "baseline": matchlib.scratch_status_payload(sweep.baseline),
        "results": [
            {"rank": rank, **mutation_evaluation_payload(evaluation)}
            for rank, evaluation in enumerate(evaluations, start=1)
        ],
    }


def render_mutation_sweep(sweep: MutationSweep, *, limit: int = 20) -> str:
    baseline = sweep.baseline
    baseline_ratio = f"{baseline.ratio:.2%}" if baseline.ratio is not None else "-"
    coverage = " ".join(
        f"{changes}-site={evaluated}/{planned}/{possible}"
        for changes, (possible, planned, evaluated) in enumerate(
            zip(
                sweep.possible_by_changes,
                sweep.planned_by_changes,
                sweep.evaluated_by_changes,
                strict=True,
            ),
            start=1,
        )
    )
    lines = [
        (
            f"baseline: state={baseline.state} match={baseline_ratio} "
            f"fuzzy={baseline.fuzzy_weighted_bytes:.0f}/{baseline.target_size} "
            f"prefix={baseline.prefix_instructions}/{baseline.target_instructions} "
            f"refs={baseline.masked_ok}/{baseline.masked_unresolved}/{baseline.masked_mismatches}"
        ),
        (
            f"variants: evaluated={len(sweep.evaluations)} possible={sweep.possible_variants} "
            f"truncated={'yes' if sweep.truncated else 'no'} "
            f"best_improves={'yes' if sweep.best_improves else 'no'} "
            f"tradeoffs={sum(bool(evaluation.tradeoffs) for evaluation in sweep.evaluations)} "
            f"best_warnings={','.join(sweep.best.tradeoffs) if sweep.best and sweep.best.tradeoffs else '-'} "
            f"stop={sweep.stop_reason or '-'}"
        ),
        (
            f"coverage (evaluated/planned/possible): {coverage}; "
            f"combinations never evaluated={sweep.unevaluated_interactions}"
        ),
        "rank  state  fuzzy delta  match    prefix     first target       refs       mutations / warnings",
    ]
    for rank, evaluation in enumerate(sweep.evaluations[:limit], start=1):
        status = evaluation.status
        ratio = f"{status.ratio:.2%}" if status.ratio is not None else "-"
        before_offset = sweep.baseline.first_target_mismatch_offset
        after_offset = status.first_target_mismatch_offset
        first_mismatch = (
            f"{f'0x{before_offset:x}' if before_offset is not None else '-'}"
            f"->{f'0x{after_offset:x}' if after_offset is not None else '-'}"
        )
        warning_suffix = (
            f" [warn:{','.join(evaluation.tradeoffs)}]"
            if evaluation.tradeoffs
            else ""
        )
        lines.append(
            f"{rank:<4}  {status.state:<5}  {status.fuzzy_weighted_bytes:>5.0f} "
            f"{evaluation.fuzzy_delta_bytes:>+5.0f}  {ratio:>7}  "
            f"{status.prefix_instructions:>4}/{status.target_instructions:<4}  "
            f"{first_mismatch:<18} "
            f"{status.masked_ok}/{status.masked_unresolved}/{status.masked_mismatches:<3}  "
            f"{evaluation.variant.label}{warning_suffix}",
        )
    return "\n".join(lines)
