from __future__ import annotations

import io
import json
import subprocess
import sys
import urllib.error
from email.message import Message
from functools import partial
from pathlib import Path

import pytest

from scripts import release_notify


def test_prepared_artifact_delivers_all_chunks_without_credentials_or_dependencies(monkeypatch, tmp_path):
    notes = tmp_path / "release-notes.md"
    artifact = tmp_path / "release-notification.json"
    notes.write_text("\n".join(f"Entry {index}: 🚀 update" for index in range(30)), encoding="utf-8")
    monkeypatch.setenv("REPO", "banteg/crimson")
    monkeypatch.setenv("TAG_NAME", "v0.21.0")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    # Exercise preparation/chunking/serialization without installing the optional renderer in the test environment.
    def render(markdown):
        return release_notify.RenderedTelegramMessage(
            text=markdown,
            entities=({"type": "bold", "offset": 0, "length": 7},),
        )

    monkeypatch.setattr(
        release_notify,
        "build_release_messages",
        partial(release_notify.build_release_messages, render_message=render, max_text_len=200),
    )
    monkeypatch.setattr(sys, "argv", ["release_notify.py", "prepare", str(notes), str(artifact)])
    release_notify.main()
    payloads = json.loads(artifact.read_text(encoding="utf-8"))
    assert len(payloads) > 1
    for index, payload in enumerate(payloads, start=1):
        assert f"({index}/{len(payloads)})" in payload["text"]
        assert len(payload["text"]) <= 200
        assert payload["entities"] == [{"type": "bold", "offset": 0, "length": 7}]
        assert payload["link_preview_options"] == {"is_disabled": True}
        assert "chat_id" not in payload
    assert "https://github.com/banteg/crimson/releases/tag/v0.21.0" in payloads[-1]["text"]

    # The artifact's script must run independently of the checkout and all site packages.
    script = Path(release_notify.__file__).resolve()
    program = """
import io, json, os, runpy, sys, urllib.request
from pathlib import Path
expected = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
sent = []
def send(request, *, timeout):
    assert request.full_url == "https://api.telegram.org/bottest-token/sendMessage"
    assert request.method == "POST"
    assert request.get_header("Content-type") == "application/json"
    assert timeout == 30
    sent.append(json.loads(request.data))
    return io.BytesIO(b'{"ok":true}')
urllib.request.urlopen = send
os.environ["TELEGRAM_BOT_TOKEN"] = "test-token"
os.environ["TELEGRAM_CHAT_ID"] = "test-chat"
sys.argv = [sys.argv[1], "send", sys.argv[2]]
runpy.run_path(sys.argv[0], run_name="__main__")
assert sent == [{**payload, "chat_id": "test-chat"} for payload in expected]
assert not {"mistune", "sulguk", "requests"}.intersection(sys.modules)
"""
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", program, str(script), str(artifact)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    assert f"sent message {len(payloads)}/{len(payloads)}" in result.stdout


@pytest.mark.parametrize(
    "failure",
    [
        urllib.error.HTTPError("https://api.telegram.org/botsecret/sendMessage", 429, "limited", Message(), None),
        urllib.error.URLError("https://api.telegram.org/botsecret/sendMessage"),
        TimeoutError("https://api.telegram.org/botsecret/sendMessage"),
        None,
    ],
)
def test_delivery_failure_stops_without_retry_or_token_disclosure(monkeypatch, failure):
    calls = []

    def send(request, *, timeout):
        calls.append(request)
        if failure is not None:
            raise failure
        return io.BytesIO(b'{"ok":false}')

    monkeypatch.setattr("urllib.request.urlopen", send)
    with pytest.raises(SystemExit, match="message 1/2") as exc:
        release_notify.send_telegram_payloads(
            bot_token="secret",
            chat_id="chat",
            payloads=[{"text": "first"}, {"text": "second"}],
        )
    assert "secret" not in str(exc.value)
    assert len(calls) == 1


def test_deploy_sender_preserves_rendered_entities(monkeypatch):
    sent = []

    def send(request, *, timeout):
        sent.append(json.loads(request.data))
        return io.BytesIO(b'{"ok":true}')

    monkeypatch.setattr("urllib.request.urlopen", send)
    release_notify.send_telegram_messages(
        bot_token="token",
        chat_id="chat",
        messages=[release_notify.RenderedTelegramMessage("🚀 ready", ({"type": "bold", "offset": 3, "length": 5},))],
    )
    assert sent == [
        {
            "chat_id": "chat",
            "text": "🚀 ready",
            "entities": [{"type": "bold", "offset": 3, "length": 5}],
            "link_preview_options": {"is_disabled": True},
        },
    ]
