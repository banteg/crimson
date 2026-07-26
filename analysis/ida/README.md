# IDA analysis

The normal IDA export commands reuse persistent, gitignored databases:

```bash
just ida-export-exe
just ida-export-grim
```

Databases and their provenance records live under `analysis/ida/databases/`.
Every run waits for analysis, reapplies the repository headers and shared
name/data maps, saves the database, and replaces the structured snapshots in
`analysis/ida/raw/`. Reuse happens through a same-directory working copy that
atomically replaces the persistent database only after IDA exits successfully,
so a failed map application leaves the previous database intact.

The wrapper verifies the input binary hash plus the IDA version and executable
fingerprint before reopening a database. It refuses mismatched or incomplete
state. Rebuild deliberately when the binary or IDA installation changes, or
when checking the persistent view against a clean analysis:

```bash
just ida-rebuild-exe
just ida-rebuild-grim
```

A rebuild moves the previous database and provenance record into
`analysis/ida/databases/backups/` before creating the replacement.

For isolated validation, override the database directory directly:

```bash
./analysis/ida/tooling/ida-export.sh \
  --database-dir /tmp/crimson-ida-databases \
  game_bins/crimsonland/1.9.93-gog/crimsonland.exe \
  /tmp/crimson-ida-export
```

The checked-in maps and structured snapshots remain the reproducible source of
truth; local IDA databases are durable working state and analysis caches.
