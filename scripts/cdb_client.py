from __future__ import annotations

import argparse
import socket


def send(host: str, port: int, line: str, timeout: float) -> str:
    sock = socket.create_connection((host, port), timeout=timeout)
    with sock:
        sock.settimeout(timeout)
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
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--break",
        dest="do_break",
        action="store_true",
        help="send :break before the command",
    )
    parser.add_argument(
        "--continue",
        dest="do_continue",
        action="store_true",
        help="send g after the command",
    )
    args = parser.parse_args()

    if args.tail is not None:
        line = f":tail {args.tail}"
    elif args.cmd:
        line = args.cmd
    else:
        raise SystemExit("Provide --cmd or --tail")

    outputs = []
    if args.do_break:
        outputs.append(send(args.host, args.port, ":break", timeout=args.timeout))
    outputs.append(send(args.host, args.port, line, timeout=args.timeout))
    if args.do_continue:
        outputs.append(send(args.host, args.port, "g", timeout=args.timeout))
    output = "\n".join([out for out in outputs if out])
    if output:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
