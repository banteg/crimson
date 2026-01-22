# WinDbg / CDB workflow

## Remote server setup (works reliably)

Just shortcuts (Windows):

```
just windbg-server
just windbg-client
just windbg-tail
```

Notes:

- `just windbg-client` uses `-bonc`, so you must `g` after attaching.
- Client output is **not** persisted by the server; if the client session drops, logs are lost.
- The server logs to `C:\Crimsonland\windbg.log` (overwritten on each server start, ASCII/ANSI).
- The server should be started by the user. Codex only connects as a client to run commands,
  and we inspect the server log file to see captured output.

- `just windbg-tail` prints any new log lines since the last read and remembers its position
  in `C:\Crimsonland\windbg.log.pos`.

- The tail script decodes ASCII by default and switches to UTF-16 if a BOM is present.

## Workflows

### User workflow (server owner)

1) Start the server (once, long-lived):

```
just windbg-server
```

2) Keep it running. The user does not need to connect a client or tail the log.

### Agent workflow (short-lived reconnects)

1) The user starts the server and keeps it running. The agent never starts a server.

2) On every agent reconnect, catch up first:

```
just windbg-tail
```

3) Then connect and run the agent commands:

```
just windbg-client
```

4) Resume the game (`g`) if needed, and disconnect the client (Ctrl+B).

Notes:

- The log is written by the server (`-logo`), so it survives client drops but resets on server restart.
- The tail script reads only new bytes from `C:\Crimsonland\windbg.log`.
