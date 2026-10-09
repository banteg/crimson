"""Required gates must reject failures and unexpected skips without coupling unrelated suites."""

from copy import deepcopy

import pytest

from scripts.ci_gate import require


def core_needs(python: bool, game: bool, oracles: bool) -> dict:
    core = python or game or oracles
    needs = {
        "changes": {
            "result": "success",
            "outputs": {
                "core": str(core).lower(),
                "python": str(python).lower(),
                "game": str(game).lower(),
                "oracles": str(oracles).lower(),
                "corpus": str(python or game).lower(),
            },
        },
    }
    for job, relevant in {
        "build-native": core,
        "build-wasm": core,
        "build-game": game,
        "corpus": python or game,
        "python": python,
        "python-report": python,
        "game-smoke": game,
        "game-parity": game,
        "oracles": oracles,
    }.items():
        needs[job] = {"result": "success" if relevant else "skipped"}
    return needs


@pytest.mark.parametrize(
    "python,game,oracles",
    [(False, False, False), (True, False, False), (False, True, False), (False, False, True), (True, True, True)],
)
def test_core_gate_accepts_exactly_the_required_jobs(python: bool, game: bool, oracles: bool) -> None:
    require("core", core_needs(python, game, oracles))


@pytest.mark.parametrize("outcome", ["failure", "cancelled", "skipped", ""])
@pytest.mark.parametrize(
    "job",
    [
        "changes",
        "build-native",
        "build-wasm",
        "build-game",
        "corpus",
        "python",
        "python-report",
        "game-smoke",
        "game-parity",
        "oracles",
    ],
)
def test_core_gate_rejects_a_required_job_that_did_not_pass(job: str, outcome: str) -> None:
    needs = core_needs(True, True, True)
    needs[job]["result"] = outcome
    with pytest.raises(ValueError):
        require("core", needs)


def test_unrelated_client_and_service_builds_do_not_fail_the_core_gate() -> None:
    needs = core_needs(False, False, False)
    needs["build-wasm"]["result"] = "failure"
    needs["build-game"]["result"] = "failure"
    require("core", needs)


@pytest.mark.parametrize("suite,build", [("client", "build-game"), ("service", "build-wasm")])
def test_client_and_service_require_both_the_build_and_consumer(suite: str, build: str) -> None:
    needs = {
        "changes": {"result": "success", "outputs": {suite: "true"}},
        build: {"result": "success"},
        suite: {"result": "success"},
    }
    require(suite, needs)
    for job in (build, suite):
        failed = deepcopy(needs)
        failed[job]["result"] = "failure"
        with pytest.raises(ValueError):
            require(suite, failed)
    needs["changes"]["outputs"][suite] = "false"
    needs[suite]["result"] = "skipped"
    needs[build]["result"] = "failure"
    require(suite, needs)


def test_missing_and_inconsistent_relevance_cannot_pass() -> None:
    needs = core_needs(True, True, True)
    needs["changes"]["outputs"]["corpus"] = "false"
    with pytest.raises(ValueError):
        require("core", needs)
    needs["changes"]["outputs"]["corpus"] = ""
    with pytest.raises(ValueError):
        require("core", needs)
