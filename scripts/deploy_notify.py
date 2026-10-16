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
import tomllib
from pathlib import Path

from release_notify import render_telegram_message, send_telegram_messages

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def build_deploy_message(*, version: str, deployed: bool, reverified: bool, commit_url: str, run_url: str) -> str:
    sha = commit_url.rsplit("/", 1)[-1][:9]
    if deployed:
        header = f"deployed **crimson.land {version}**"
        replays = "every active run reverified" if reverified else "replay checks reused from the live deployment"
        detail = f"commit [{sha}]({commit_url}), {replays}"
    else:
        header = f"deploy failed: **crimson.land {version}**"
        detail = f"commit [{sha}]({commit_url}) is not live"
    return "\n\n".join([header, detail, f"[deploy run]({run_url})"])


def main() -> None:
    server, repo = os.environ["GITHUB_SERVER_URL"], os.environ["GITHUB_REPOSITORY"]
    message = build_deploy_message(
        version=tomllib.loads(PYPROJECT.read_text())["project"]["version"],
        deployed=os.environ["DEPLOY_RESULT"] == "success",
        reverified=os.environ.get("REVERIFIED") == "true",
        commit_url=f"{server}/{repo}/commit/{os.environ['GITHUB_SHA']}",
        run_url=f"{server}/{repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}",
    )
    send_telegram_messages(
        bot_token=os.environ["TELEGRAM_BOT_TOKEN"],
        chat_id=os.environ["TELEGRAM_CHAT_ID"],
        messages=[render_telegram_message(message)],
    )


if __name__ == "__main__":
    main()
