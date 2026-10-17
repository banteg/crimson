"""Required gates must reject failures and unexpected skips without coupling unrelated suites."""

import os
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.ci_gate import require


def core_needs(python: bool, game: bool, oracles: bool) -> dict:
    core = python or game or oracles
    needs = {
        "changes": {
            "result": "success",
            "outputs": {
                "release": "false",
                "core": str(core).lower(),
                "python": str(python).lower(),
                "game": str(game).lower(),
                "oracles": str(oracles).lower(),
                "corpus": str(core).lower(),
            },
        },
    }
    for job, relevant in {
        "build-native": core,
        "build-wasm": core,
        "build-game": game,
        "corpus": core,
        "python": python,
        "python-report": python,
        "game-smoke": game,
        "game-parity": game,
        "game-coop": game,
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
        "game-coop",
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
        "changes": {"result": "success", "outputs": {suite: "true", "release": "false"}},
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


@pytest.mark.parametrize("outcome", ["failure", "cancelled", "skipped"])
@pytest.mark.parametrize("job", ["build-wasm", "build-game"])
def test_master_requires_release_builds_even_when_tests_are_irrelevant(job: str, outcome: str) -> None:
    needs = core_needs(False, False, False)
    needs["changes"]["outputs"]["release"] = "true"
    needs["build-wasm"]["result"] = "success"
    needs["build-game"]["result"] = "success"
    require("core", needs)
    needs[job]["result"] = outcome
    with pytest.raises(ValueError):
        require("core", needs)


def test_master_requires_web_package_without_running_service_or_desktop_tests() -> None:
    needs = {
        "changes": {"result": "success", "outputs": {"release": "true", "client": "false", "service": "false"}},
        "build-game": {"result": "success"},
        "build-wasm": {"result": "success"},
        "client": {"result": "success"},
        "service": {"result": "skipped"},
    }
    require("client", needs)
    require("service", needs)
    needs["client"]["result"] = "skipped"
    with pytest.raises(ValueError):
        require("client", needs)


@pytest.fixture(params=[False, True], ids=["default-env", "inherited-git-env"])
def detector_checkout(
    tmp_path: Path, request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, dict[str, str]]:
    source = Path(__file__).resolve().parents[1]
    checkout = tmp_path / "checkout"
    for name in ("scripts/ci_changed_paths.py", "scripts/build_identity.py", "crimson-core/sources.json"):
        target = checkout / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)

    if request.param:
        for name in ("GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY"):
            monkeypatch.setenv(name, str(tmp_path / "caller" / name))

    # Worktree/hook Git variables must not redirect these commands to the caller's repository.
    env = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_ALLOW_PROTOCOL="file",
        GIT_CEILING_DIRECTORIES=str(tmp_path),
    )
    git = shutil.which("git")
    assert git is not None
    origin = tmp_path / "origin.git"
    for args in (
        ["init", "-q", "--initial-branch=master", "--template=", str(checkout)],
        ["add", "."],
        ["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"],
        ["clone", "--bare", "--quiet", "--no-hardlinks", str(checkout), str(origin)],
        ["remote", "add", "origin", origin.as_uri()],
    ):
        subprocess.run([git, *args], cwd=checkout, env=env, capture_output=True, check=True)
    # Pin Git as well as cwd: even an accidental cwd change cannot select the real repository.
    env.update(GIT_DIR=str(checkout / ".git"), GIT_WORK_TREE=str(checkout))
    return checkout, env


@pytest.mark.parametrize("release,branch,success", [(False, "master", True), (True, "master", True), (True, "feature", False)])
def test_release_only_detector_keeps_slow_suites_skipped_and_rejects_other_branches(
    detector_checkout: tuple[Path, dict[str, str]], release: bool, branch: str, success: bool,
) -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github/workflows/core.yml").read_text()
    block = workflow.split("      - id: detect\n", 1)[1].split("\n  build-native:", 1)[0]
    script = "\n".join(line[10:] for line in block.split("        run: |\n", 1)[1].splitlines())
    checkout, env = detector_checkout
    output = checkout / "outputs"
    bash = shutil.which("bash")
    assert bash is not None
    result = subprocess.run(
        [bash, "-e", "-o", "pipefail", "-c", script],
        cwd=checkout,
        env={**env, "RELEASE": str(release).lower(), "BUILD_REF": f"refs/heads/{branch}", "BASE_SHA": "HEAD", "GITHUB_OUTPUT": str(output)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) == success, result.stderr
    # The non-release case really runs the shallow fetch, confined to the disposable checkout.
    assert (checkout / ".git/shallow").exists() is (not release)
    if success:
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        assert values.pop("release") == str(release).lower()
        assert set(values.values()) == {"false"}
    else:
        assert "require master" in result.stdout
