# /// script
# requires-python = ">=3.14"
# dependencies = [
#     "mistune>=3.2.0",
#     "requests>=2.32.5",
#     "sulguk>=0.11.1",
# ]
# ///
"""Tell the release chat how a crimson.land production deploy ended (deploy.yml)."""

from __future__ import annotations

import os
import re
import tomllib
import urllib.request
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def live_revision() -> str | None:
    request = urllib.request.Request(
        "https://crimson.land/deployment.txt",
        headers={"Cache-Control": "no-cache", "User-Agent": "crimson-deploy-notify/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            sha = response.read(128).decode("ascii").strip()
    except (OSError, UnicodeError, ValueError):
        return None
    return sha if re.fullmatch(r"[0-9a-f]{40}", sha) else None


def build_deploy_message(
    *,
    version: str,
    prepare_result: str,
    deploy_result: str,
    reverified: bool,
    commit_url: str,
    run_url: str,
    live_sha: str | None,
) -> str:
    commit = commit_url.rsplit("/", 1)[-1]
    sha = commit[:9]
    if prepare_result != "success":
        header = f"deploy blocked: **crimson.land {version}**"
        detail = f"preflight failed for commit [{sha}]({commit_url}); this attempt did not publish"
    elif deploy_result == "success":
        header = f"deploy completed: **crimson.land {version}**"
        replays = "every active run reverified" if reverified else "replay checks reused from the live deployment"
        detail = f"commit [{sha}]({commit_url}), {replays}"
    else:
        header = f"deploy attempt failed: **crimson.land {version}**"
        detail = f"deployment or post-deploy checks failed for commit [{sha}]({commit_url})"
    if live_sha == commit:
        live = f"commit [{sha}]({commit_url}) is live"
    elif live_sha:
        live_url = f"{commit_url.rsplit('/', 1)[0]}/{live_sha}"
        live = f"live commit: [{live_sha[:9]}]({live_url})"
    else:
        live = "live revision could not be checked"
    return "\n\n".join([header, detail, live, f"[deploy run]({run_url})"])


def main() -> None:
    # Direct script execution adds scripts/ to sys.path; its PEP 723 dependencies live in uv's script environment.
    from release_notify import render_telegram_message, send_telegram_messages  # ty: ignore[unresolved-import]

    server, repo = os.environ["GITHUB_SERVER_URL"], os.environ["GITHUB_REPOSITORY"]
    message = build_deploy_message(
        version=tomllib.loads(PYPROJECT.read_text())["project"]["version"],
        prepare_result=os.environ["PREPARE_RESULT"],
        deploy_result=os.environ["DEPLOY_RESULT"],
        reverified=os.environ.get("REVERIFIED") == "true",
        commit_url=f"{server}/{repo}/commit/{os.environ['GITHUB_SHA']}",
        run_url=f"{server}/{repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}",
        live_sha=live_revision(),
    )
    send_telegram_messages(
        bot_token=os.environ["TELEGRAM_BOT_TOKEN"],
        chat_id=os.environ["TELEGRAM_CHAT_ID"],
        messages=[render_telegram_message(message)],
    )


if __name__ == "__main__":
    main()
