from __future__ import annotations

import argparse
import socket


def send(host: str, port: int, line: str) -> str:
    sock = socket.create_connection((host, port), timeout=5.0)
    with sock:
        sock.sendall((line.rstrip() + "\n").encode("utf-8"))
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data.decode("utf-8", errors="replace"))
            if "<<<END>>>" in chunks[-1]:
                break
    text = "".join(chunks)
    return text.replace("<<<END>>>\n", "").rstrip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Send commands to cdb_bridge.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=31337)
    parser.add_argument("--cmd", help="command to send")
    parser.add_argument("--tail", type=int, help="tail lines from log")
    args = parser.parse_args()

    if args.tail is not None:
        line = f":tail {args.tail}"
    elif args.cmd:
        line = args.cmd
    else:
        raise SystemExit("Provide --cmd or --tail")

    output = send(args.host, args.port, line)
    if output:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
