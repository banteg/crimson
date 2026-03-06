# /// script
# requires-python = ">=3.14"
# dependencies = [
#     "mistune>=3.2.0",
#     "requests>=2.32.5",
#     "sulguk>=0.11.1",
# ]
# ///
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

import mistune
import requests
import sulguk

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

TELEGRAM_TEXT_LIMIT = 4096


@dataclass(frozen=True)
class RenderedTelegramMessage:
    text: str
    entities: tuple[object, ...]


def _compile_patterns(repo: str) -> tuple[re.Pattern[str], re.Pattern[str]]:
    return (
        re.compile(rf"(https://github.com/{re.escape(repo)}/pull/(\d+))"),
        re.compile(rf"(https://github.com/{re.escape(repo)}/compare/(.*))"),
    )


def _build_release_lines(*, repo: str, tag: str, body: str, release_url: str) -> list[str]:
    pull_re, compare_re = _compile_patterns(repo)
    lines = body.splitlines()
    release_lines = [pull_re.sub(r"[#\2](\1)", line) for line in lines if pull_re.search(line)]
    compare_match = compare_re.search(body)
    if compare_match:
        release_lines.append(compare_re.sub(r"compare [\2](\1)", compare_match.group(0)))
    release_lines.append(f"release [{tag}]({release_url})")
    return release_lines


def _chunk_header(*, repo: str, tag: str, chunk_index: int, chunk_total: int) -> str:
    header = f"release **{repo} {tag}**"
    if chunk_total == 1:
        return header
    return f"{header} ({chunk_index}/{chunk_total})"


def _format_chunk(header: str, lines: Sequence[str]) -> str:
    if not lines:
        return header
    return "\n\n".join([header, "\n".join(lines)])


def _render_telegram_message(markdown: str) -> RenderedTelegramMessage:
    html = mistune.html(markdown)
    rendered = sulguk.transform_html(html)
    return RenderedTelegramMessage(text=rendered.text, entities=tuple(rendered.entities))


def _split_release_messages(
    *,
    repo: str,
    tag: str,
    lines: Sequence[str],
    chunk_total: int,
    render_message: Callable[[str], RenderedTelegramMessage],
    max_text_len: int,
) -> list[RenderedTelegramMessage]:
    messages: list[RenderedTelegramMessage] = []
    line_index = 0
    chunk_index = 1
    while line_index < len(lines):
        chunk_lines: list[str] = []
        rendered_chunk: RenderedTelegramMessage | None = None
        while line_index < len(lines):
            candidate_lines = [*chunk_lines, lines[line_index]]
            candidate = _format_chunk(
                _chunk_header(repo=repo, tag=tag, chunk_index=chunk_index, chunk_total=chunk_total),
                candidate_lines,
            )
            rendered_candidate = render_message(candidate)
            if len(rendered_candidate.text) > max_text_len:
                if not chunk_lines:
                    raise ValueError(f"release line exceeds Telegram limit: {lines[line_index]!r}")
                break
            chunk_lines = candidate_lines
            rendered_chunk = rendered_candidate
            line_index += 1
        if rendered_chunk is None:
            raise AssertionError("release chunking failed to produce a message")
        messages.append(rendered_chunk)
        chunk_index += 1
    return messages


def build_release_messages(
    *,
    repo: str,
    tag: str,
    body: str,
    release_url: str,
    render_message: Callable[[str], RenderedTelegramMessage] = _render_telegram_message,
    max_text_len: int = TELEGRAM_TEXT_LIMIT,
) -> list[RenderedTelegramMessage]:
    lines = _build_release_lines(repo=repo, tag=tag, body=body, release_url=release_url)
    chunk_total = 1
    while True:
        messages = _split_release_messages(
            repo=repo,
            tag=tag,
            lines=lines,
            chunk_total=chunk_total,
            render_message=render_message,
            max_text_len=max_text_len,
        )
        if len(messages) == chunk_total:
            return messages
        chunk_total = len(messages)


def fetch_release(*, repo: str, tag: str, github_token: str | None) -> tuple[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    resp = requests.get(
        f"https://api.github.com/repos/{repo}/releases/tags/{tag}",
        headers=headers,
        timeout=30,
    )
    try:
        resp.raise_for_status()
    except requests.HTTPError:
        print(f"github api error: {resp.status_code} {resp.text}")
        raise
    release = resp.json()
    body = release.get("body")
    if body is None:
        raise KeyError(f"release body missing (keys={sorted(release.keys())})")
    release_url = release.get("html_url")
    if not isinstance(release_url, str) or not release_url:
        raise KeyError(f"release html_url missing (keys={sorted(release.keys())})")
    return body, release_url


def send_telegram_messages(
    *,
    bot_token: str,
    chat_id: str,
    messages: Sequence[RenderedTelegramMessage],
) -> None:
    total = len(messages)
    print(f"prepared {total} Telegram release message(s)")
    for index, message in enumerate(messages, start=1):
        payload = {
            "chat_id": chat_id,
            "text": message.text,
            "entities": list(message.entities),
            "link_preview_options": {"is_disabled": True},
        }
        resp = requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json=payload,
            timeout=30,
        )
        try:
            resp.raise_for_status()
        except requests.HTTPError:
            print(f"telegram api error on message {index}/{total}: {resp.status_code} {resp.text}")
            raise
        print(f"sent message {index}/{total} to {chat_id}")


def main() -> None:
    repo = os.environ["REPO"]
    tag = os.environ["TAG_NAME"]
    bot_token = os.environ["TELEGRAM_BOT_TOKEN"]
    chat_id = os.environ["TELEGRAM_CHAT_ID"]
    github_token = os.environ.get("GITHUB_TOKEN")

    body, release_url = fetch_release(repo=repo, tag=tag, github_token=github_token)
    messages = build_release_messages(repo=repo, tag=tag, body=body, release_url=release_url)
    send_telegram_messages(bot_token=bot_token, chat_id=chat_id, messages=messages)


if __name__ == "__main__":
    main()
