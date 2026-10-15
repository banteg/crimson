set shell := ["bash", "-uc"]

default:
    @just --list

# Build the native desktop client; accepts build options such as --package.
[positional-arguments]
build *args:
    uv run python crimson-core/client/build.py --target native "$@"

# Build and launch the native client; accepts a game directory and --watch.
[positional-arguments]
run *args: build
    ./crimson-core/build/app/crimson "$@"

# Tests
test *args:
    uv run pytest {{ args }}

check *args:
    uv run ruff check .
    uv run ty check src crimson-re/src tests
    uv run scripts/check_docs.py
    uv run crimson match resolved-name-audit --check
    uv run crimson native verify --require-game-closure --allow-absent-toolchain
    uv run crimson match regressions
    ast-grep scan
    ast-grep test
    uv run pytest {{ args }}

ty:
    uv run ty check src crimson-re/src tests

# Docs
docs-build:
    uv run zensical build

docs-check:
    uv run scripts/check_docs.py
