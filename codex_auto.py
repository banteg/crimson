#!/usr/bin/env python3
import argparse
import os
import subprocess
import tempfile
from typing import Optional, Tuple

DEFAULT_PROMPT = "Continue reverse engineering. Map structures and functions systematically."
MAIN_MODEL = "gpt-5.2-codex"
MAIN_REASONING = "xhigh"
HELPER_MODEL = "gpt-5.2-codex"
HELPER_REASONING = "medium"
MAX_ITERATIONS = 20
DEFAULT_SESSION = "last"
COLOR_MODE = "always"


def _read_last_message(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except FileNotFoundError:
        return ""


def _build_args(
    *,
    model: str,
    reasoning: str,
    session: Optional[str],
    output_path: str,
) -> list[str]:
    args = [
        "codex",
        "exec",
        "--output-last-message",
        output_path,
    ]
    if COLOR_MODE:
        args.append(f"--color={COLOR_MODE}")
    if model:
        args.extend(["--model", model])
    if reasoning:
        args.extend(["-c", f"model_reasoning_effort={reasoning}"])

    if session:
        args.append("resume")
        if session == "last":
            args.append("--last")
        else:
            args.append(session)
        args.append("-")
    else:
        args.append("-")
    return args


def run_codex(
    prompt: str,
    model: str,
    reasoning: str,
    session: Optional[str],
) -> Tuple[str, str]:
    """Run codex exec and return (final_message, raw_output)."""
    with tempfile.NamedTemporaryFile(prefix="codex_last_message_", delete=False) as tmp:
        output_path = tmp.name

    cmd = _build_args(
        model=model,
        reasoning=reasoning,
        session=session,
        output_path=output_path,
    )

    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    if process.stdin:
        process.stdin.write(prompt)
        process.stdin.flush()
        process.stdin.close()

    output_lines: list[str] = []
    if process.stdout:
        for line in process.stdout:
            print(line, end="", flush=True)
            output_lines.append(line)
    process.wait(timeout=300)

    raw_output = "".join(output_lines)
    final_message = _read_last_message(output_path)

    if not final_message:
        final_message = raw_output.strip()

    try:
        os.unlink(output_path)
    except FileNotFoundError:
        pass

    return final_message, raw_output


def get_response(output: str, helper_model: str, helper_reasoning: str) -> tuple[str, bool]:
    """Ask helper LLM what to respond with. Returns (response, should_continue)."""
    
    prompt = f"""You're guiding an automated reverse engineering session as an overseer. The main AI just output:

---
{output}
---

If it's asking a question or waiting for direction, give a brief answer (like "yes", keep exploring, go deeper).
Before replying, check whether the git worktree is clean. If it isn't clean, remind the main AI to commit its work (conventional commits).
If it seems done or stuck, say "STOP".

Reply with just your response, nothing else."""

    response, _ = run_codex(
        prompt=prompt,
        model=helper_model,
        reasoning=helper_reasoning,
        session=None,
    )

    response = response.strip() or "Yes, continue."
    should_continue = "STOP" not in response.upper()
    return response, should_continue


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("prompt", nargs="?", default=DEFAULT_PROMPT)
    parser.add_argument(
        "-i",
        "--initial-prompt",
        help="Override the initial prompt for the first iteration.",
    )
    parser.add_argument(
        "-s",
        "--session",
        default=DEFAULT_SESSION,
        help="Resume session ID or 'last'.",
    )
    args = parser.parse_args()

    current_prompt = args.initial_prompt or args.prompt
    session_id = args.session if args.session != "new" else None
    
    for i in range(MAX_ITERATIONS):
        print(f"\n{'='*60}\n[iter {i+1}] Running main codex...\n{'='*60}")
        
        output, raw_output = run_codex(
            prompt=current_prompt,
            model=MAIN_MODEL,
            reasoning=MAIN_REASONING,
            session=session_id,
        )
        if not raw_output.strip() and output:
            print(output)

        print(f"\n[iter {i+1}] Getting helper response...")
        response, should_continue = get_response(
            output, HELPER_MODEL, HELPER_REASONING
        )
        print(f"[helper]: {response}")
        
        if not should_continue:
            print("\n[done] Helper said stop.")
            break
        
        current_prompt = response

    print(f"\nFinished after {i+1} iterations.")


if __name__ == "__main__":
    main()
