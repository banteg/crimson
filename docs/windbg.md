# WinDbg / CDB workflow

## Remote server setup (works reliably)

Server (run once, long-lived):

```
cdb -server tcp:port=5005,password=secret -noio -pn crimsonland.exe
```

Client (reconnect as needed):

```
cdb -remote tcp:server=127.0.0.1,port=5005,password=secret -bonc
```

Notes:
- `-bonc` breaks on connect, so you must `g` after attaching.
