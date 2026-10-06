from __future__ import annotations

import base64
import json
import stat
from typing import Any

import pytest
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from crimson.leaderboard import Identity, Leaderboard, LeaderboardError
from crimson.leaderboard.identity import IDENTITY_FILE, login_message, run_message
from crimson.replay import load_replay
from crimson.replay.codec import inflate_replay_payload
from tests.support.replay_runner_helpers import RECORDED_REPLAYS

_URL = "https://crimson.test/api"


@pytest.fixture(scope="module")
def replay():
    return load_replay(min(RECORDED_REPLAYS, key=lambda path: path.stat().st_size).read_bytes())


class _Service:
    """Answers like the leaderboard service, with one scripted status per upload."""

    def __init__(self, *statuses: int | OSError, login_url: str = "https://crimson.test/login/once") -> None:
        self.statuses = list(statuses)
        self.login_url = login_url
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, url: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        self.calls.append((url, body))
        if url.endswith("/auth/challenge"):
            return 200, {"challenge": "c0ffee"}
        if url.endswith("/auth/login"):
            return 200, {"url": self.login_url}
        status = self.statuses.pop(0)
        if isinstance(status, OSError):
            raise status
        return status, {"reason": "aim out of view"} if status == 422 else {}


def _finish(leaderboard: Leaderboard) -> list[str]:
    """Wait for the started jobs, as frames would, and collect their lines."""
    lines = []
    while leaderboard._pending:
        leaderboard._pending[0].result()
        lines += leaderboard.drain()
    return lines


def test_the_key_is_made_once_and_kept_private(tmp_path) -> None:
    identity = Identity.load_or_create(tmp_path)

    assert Identity.load_or_create(tmp_path).public_key == identity.public_key
    assert stat.S_IMODE((tmp_path / IDENTITY_FILE).stat().st_mode) == 0o600
    # A run signature never passes as a login.
    signature = identity.sign_run(b"payload", "banteg")
    VerifyKey(identity.public_key).verify(run_message(b"payload", "banteg"), signature)
    with pytest.raises(BadSignatureError):
        VerifyKey(identity.public_key).verify(login_message("payload"), signature)


def test_a_released_run_uploads_signed_under_its_name(tmp_path, replay) -> None:
    service = _Service(201)
    leaderboard = Leaderboard(tmp_path, url=_URL, transport=service)

    leaderboard.hold(replay)
    leaderboard.release("banteg")
    lines = _finish(leaderboard)

    [(url, envelope)] = service.calls
    assert url == f"{_URL}/runs"
    payload = inflate_replay_payload(base64.b64decode(envelope["replay"]))
    assert envelope["name"] == "banteg"
    assert bytes.fromhex(envelope["public_key"]) == leaderboard.identity.public_key
    VerifyKey(bytes.fromhex(envelope["public_key"])).verify(run_message(payload, "banteg"), bytes.fromhex(envelope["signature"]))
    assert load_replay(base64.b64decode(envelope["replay"])) == replay
    assert lines[-1].startswith("leaderboard: uploaded run")
    assert leaderboard.waiting == 0


def test_runs_wait_offline_and_go_with_a_later_pass(tmp_path, replay) -> None:
    offline = Leaderboard(tmp_path, url=_URL, transport=_Service(OSError("no route")))
    offline.hold(replay)
    offline.release("banteg")
    assert "can't reach" in _finish(offline)[-1]
    assert offline.waiting == 1

    service = _Service(201)
    relaunched = Leaderboard(tmp_path, url=_URL, transport=service)
    assert relaunched.waiting == 1
    relaunched.tick(0.0)
    _finish(relaunched)

    assert len(service.calls) == 1
    assert relaunched.waiting == 0


@pytest.mark.parametrize(("status", "rejected"), [(409, 0), (422, 1)])
def test_the_service_settles_duplicate_and_refused_runs(tmp_path, replay, status, rejected) -> None:
    leaderboard = Leaderboard(tmp_path, url=_URL, transport=_Service(status))
    leaderboard.hold(replay)
    leaderboard.release("banteg")
    _finish(leaderboard)

    assert leaderboard.waiting == 0
    kept = sorted((tmp_path / "leaderboard" / "rejected").glob("*.json"))
    assert len(kept) == rejected
    if rejected:
        assert json.loads(kept[0].read_bytes())["reason"] == "aim out of view"


def test_quitting_on_the_results_queues_the_held_run(tmp_path, replay) -> None:
    service = _Service()
    leaderboard = Leaderboard(tmp_path, url=_URL, transport=service)
    leaderboard.hold(replay)

    leaderboard.close("banteg")

    assert service.calls == []
    [queued] = (tmp_path / "leaderboard" / "outbox").glob("*.json")
    assert json.loads(queued.read_bytes())["name"] == "banteg"


def test_login_signs_the_challenge_and_stays_on_the_service(tmp_path) -> None:
    service = _Service()
    leaderboard = Leaderboard(tmp_path, url=_URL, transport=service)

    assert leaderboard.login().result() == "https://crimson.test/login/once"
    _, body = service.calls[-1]
    VerifyKey(leaderboard.identity.public_key).verify(login_message("c0ffee"), bytes.fromhex(body["signature"]))

    elsewhere = Leaderboard(tmp_path, url=_URL, transport=_Service(login_url="https://evil.test/login"))
    with pytest.raises(LeaderboardError):
        elsewhere.login().result()


def test_a_key_moves_between_machines_by_export_and_import(tmp_path) -> None:
    from typer.testing import CliRunner

    from crimson.cli import app

    runner = CliRunner()
    home, laptop = tmp_path / "home", tmp_path / "laptop"
    shown = runner.invoke(app, ["identity", "show", "--base-dir", str(home)])
    assert runner.invoke(app, ["identity", "export", str(tmp_path / "key"), "--base-dir", str(home)]).exit_code == 0
    Identity.load_or_create(laptop)

    refused = runner.invoke(app, ["identity", "import", str(tmp_path / "key"), "--base-dir", str(laptop)])
    replaced = runner.invoke(app, ["identity", "import", str(tmp_path / "key"), "--base-dir", str(laptop), "--replace"])

    assert refused.exit_code != 0
    assert replaced.exit_code == 0
    assert Identity.load_or_create(laptop).public_key == Identity.load_or_create(home).public_key
    assert Identity.load_or_create(home).public_key.hex() in shown.output


def test_without_a_service_runs_stay_on_the_machine(tmp_path, replay) -> None:
    service = _Service()
    leaderboard = Leaderboard(tmp_path, url="", transport=service)
    leaderboard.hold(replay)
    leaderboard.release("banteg")
    leaderboard.tick(0.0)
    _finish(leaderboard)

    assert service.calls == []
    assert leaderboard.waiting == 1
    with pytest.raises(LeaderboardError):
        leaderboard.login().result()
