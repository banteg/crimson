from __future__ import annotations

import io
from urllib.error import URLError

import pytest

from scripts.deploy_notify import build_deploy_message, live_revision

SHA = "1ea989d4f654918ceec1ad2ef0967c52060cbd4d"
OLD_SHA = "9de661afab5a2353fc3dff751affa7e2ae8854c8"
COMMIT = f"https://github.com/banteg/crimson/commit/{SHA}"


@pytest.mark.parametrize(
    ("prepare", "deploy", "live", "header", "status"),
    [
        ("failure", "skipped", OLD_SHA, "deploy blocked:", "this attempt did not publish"),
        ("failure", "skipped", SHA, "deploy blocked:", "is live"),
        ("success", "failure", SHA, "deploy attempt failed:", "is live"),
        ("success", "failure", OLD_SHA, "deploy attempt failed:", f"live commit: [{OLD_SHA[:9]}]"),
        ("success", "success", SHA, "deploy completed:", "is live"),
        ("success", "success", OLD_SHA, "deploy completed:", f"live commit: [{OLD_SHA[:9]}]"),
        ("success", "failure", None, "deploy attempt failed:", "live revision could not be checked"),
    ],
)
def test_attempt_outcome_does_not_determine_live_state(prepare, deploy, live, header, status):
    message = build_deploy_message(
        version="0.18.0",
        prepare_result=prepare,
        deploy_result=deploy,
        reverified=True,
        commit_url=COMMIT,
        run_url="https://github.com/banteg/crimson/actions/runs/123",
        live_sha=live,
    )
    assert message.startswith(header)
    assert status in message
    assert "is not live" not in message
    assert ("every active run reverified" in message) == (prepare == deploy == "success")


@pytest.mark.parametrize("body", [b"unavailable", b"<html>error</html>", b"\xff", b"", b"a" * 41])
def test_invalid_marker_is_unknown(monkeypatch, body):
    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: io.BytesIO(body))
    assert live_revision() is None


def test_live_marker_has_timeout_and_bypasses_cache(monkeypatch):
    def open_marker(request, *, timeout):
        assert request.full_url == "https://crimson.land/deployment.txt"
        assert request.get_header("Cache-control") == "no-cache"
        assert timeout == 10
        return io.BytesIO(f"{SHA}\n".encode())

    monkeypatch.setattr("urllib.request.urlopen", open_marker)
    assert live_revision() == SHA


def test_unreachable_marker_is_unknown(monkeypatch):
    def unavailable(*args, **kwargs):
        raise URLError("offline")

    monkeypatch.setattr("urllib.request.urlopen", unavailable)
    assert live_revision() is None
