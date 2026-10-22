# /// script
# requires-python = ">=3.14"
# dependencies = [
#     "mistune>=3.2.0",
#     "sulguk>=0.11.1",
# ]
# ///
from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

TELEGRAM_TEXT_LIMIT = 4096


@dataclass(frozen=True)
class RenderedTelegramMessage:
    text: str
    entities: tuple[object, ...]


def _build_release_lines(*, tag: str, body: str, release_url: str) -> list[str]:
    """The release notes, one changelog entry per line, then the release link."""

    return [*body.strip().splitlines(), "", f"release [{tag}]({release_url})"]


def _chunk_header(*, repo: str, tag: str, chunk_index: int, chunk_total: int) -> str:
    header = f"release **{repo} {tag}**"
    if chunk_total == 1:
        return header
    return f"{header} ({chunk_index}/{chunk_total})"


def _format_chunk(header: str, lines: Sequence[str]) -> str:
    if not lines:
        return header
    return "\n\n".join([header, "\n".join(lines)])


def render_telegram_message(markdown: str) -> RenderedTelegramMessage:
    # Only preparation needs third-party packages; delivery runs on system Python.
    import mistune
    import sulguk

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
    render_message: Callable[[str], RenderedTelegramMessage] = render_telegram_message,
    max_text_len: int = TELEGRAM_TEXT_LIMIT,
) -> list[RenderedTelegramMessage]:
    lines = _build_release_lines(tag=tag, body=body, release_url=release_url)
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


def message_payloads(messages: Sequence[RenderedTelegramMessage]) -> list[dict[str, object]]:
    return [
        {
            "text": message.text,
            "entities": list(message.entities),
            "link_preview_options": {"is_disabled": True},
        }
        for message in messages
    ]


def send_telegram_messages(
    *,
    bot_token: str,
    chat_id: str,
    messages: Sequence[RenderedTelegramMessage],
) -> None:
    send_telegram_payloads(bot_token=bot_token, chat_id=chat_id, payloads=message_payloads(messages))


def send_telegram_payloads(*, bot_token: str, chat_id: str, payloads: Sequence[dict[str, object]]) -> None:
    total = len(payloads)
    for index, payload in enumerate(payloads, start=1):
        request = urllib.request.Request(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            data=json.dumps({**payload, "chat_id": chat_id}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                result = json.load(response)
        except (urllib.error.URLError, TimeoutError) as exc:
            # The request URL contains the bot token; do not print it or retry an uncertain send.
            raise SystemExit(f"Telegram request failed on message {index}/{total}: {type(exc).__name__}") from None
        if result.get("ok") is not True:
            raise SystemExit(f"Telegram rejected message {index}/{total}")
        print(f"sent message {index}/{total}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare release notifications or deliver prepared messages.")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("notes", type=Path)
    prepare.add_argument("output", type=Path)
    send = commands.add_parser("send")
    send.add_argument("payload", type=Path)
    args = parser.parse_args()

    if args.command == "send":
        send_telegram_payloads(
            bot_token=os.environ["TELEGRAM_BOT_TOKEN"],
            chat_id=os.environ["TELEGRAM_CHAT_ID"],
            payloads=json.loads(args.payload.read_text(encoding="utf-8")),
        )
        return

    repo = os.environ["REPO"]
    tag = os.environ["TAG_NAME"]
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    messages = build_release_messages(
        repo=repo,
        tag=tag,
        body=args.notes.read_text(encoding="utf-8"),
        release_url=f"{server}/{repo}/releases/tag/{tag}",
    )
    args.output.write_text(json.dumps(message_payloads(messages), ensure_ascii=False), encoding="utf-8")
    print(f"prepared {len(messages)} Telegram message(s)")


if __name__ == "__main__":
    main()
