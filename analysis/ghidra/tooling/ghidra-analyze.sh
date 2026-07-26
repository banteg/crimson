#!/bin/bash
# Wrapper script for Ghidra headless analysis
# Handles project creation/cleanup and provides a simpler interface

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Find analyzeHeadless
ANALYZE_HEADLESS=$("$SCRIPT_DIR/find-ghidra.sh")
GHIDRA_HOME=$(dirname "$(dirname "$ANALYZE_HEADLESS")")

show_help() {
    cat << 'EOF'
Usage: ghidra-analyze.sh [options] <binary>

Analyze a binary file using Ghidra's headless analyzer.

Options:
  -o, --output <dir>       Output directory for results (default: current dir)
  -s, --script <name>      Post-analysis script to run (can be repeated)
  -a, --script-args <args> Arguments for the last specified script
  --script-path <path>     Additional script search path
  -p, --processor <id>     Processor/architecture (e.g., x86:LE:32:default)
  -c, --cspec <id>         Compiler spec (e.g., gcc, windows)
  --no-analysis            Skip auto-analysis
  --timeout <seconds>      Analysis timeout per file
  --keep-project           Keep the Ghidra project after analysis
  --persistent             Reuse an existing project or create it once
  --rebuild                Back up and cleanly rebuild a persistent project
  --project-dir <dir>      Directory for Ghidra project (default: /tmp)
  --project-name <name>    Project name (default: auto-generated)
  -v, --verbose            Verbose output
  -h, --help               Show this help

Environment:
  GHIDRA_LOG_DIR            Directory for transient analyzer logs
  PYTHON_BIN                Python interpreter used for provenance checks

Built-in Scripts (use with -s):
  ExportAll.java           Export structured functions, calls, strings, and summary
  ExportSymbols.java       Export all symbols and their addresses

Examples:
  # Basic structured analysis export
  ghidra-analyze.sh -s ExportAll.java -o ./output myprogram

  # Analyze with specific architecture
  ghidra-analyze.sh -p ARM:LE:32:v7 firmware.bin

  # Add a complete symbol-table export
  ghidra-analyze.sh -s ExportAll.java -s ExportSymbols.java binary

  # Keep project for later use
  ghidra-analyze.sh --keep-project --project-name MyProject binary

  # Reuse a persistent project
  ghidra-analyze.sh --persistent --project-dir ./projects \
    --project-name MyProject binary
EOF
}

# Default values
OUTPUT_DIR="."
SCRIPTS=()
SCRIPT_ARGS=()
SCRIPT_PATH=""
PROCESSOR=""
CSPEC=""
NO_ANALYSIS=""
TIMEOUT=""
KEEP_PROJECT=false
PERSISTENT=false
REBUILD=false
PROJECT_DIR="/tmp"
PROJECT_NAME=""
PROJECT_NAME_SET=false
VERBOSE=false
BINARY=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -s|--script)
            SCRIPTS+=("$2")
            shift 2
            ;;
        -a|--script-args)
            # Associate args with the last script
            if [[ ${#SCRIPTS[@]} -gt 0 ]]; then
                SCRIPT_ARGS+=("${#SCRIPTS[@]}:$2")
            fi
            shift 2
            ;;
        --script-path)
            SCRIPT_PATH="$2"
            shift 2
            ;;
        -p|--processor)
            PROCESSOR="$2"
            shift 2
            ;;
        -c|--cspec)
            CSPEC="$2"
            shift 2
            ;;
        --no-analysis)
            NO_ANALYSIS="-noanalysis"
            shift
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --keep-project)
            KEEP_PROJECT=true
            shift
            ;;
        --persistent)
            PERSISTENT=true
            KEEP_PROJECT=true
            shift
            ;;
        --rebuild)
            REBUILD=true
            PERSISTENT=true
            KEEP_PROJECT=true
            shift
            ;;
        --project-dir)
            PROJECT_DIR="$2"
            shift 2
            ;;
        --project-name)
            PROJECT_NAME="$2"
            PROJECT_NAME_SET=true
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        -*)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
        *)
            BINARY="$1"
            shift
            ;;
    esac
done

if [[ -z "$BINARY" ]]; then
    echo "Error: No binary file specified" >&2
    show_help
    exit 1
fi

if [[ ! -f "$BINARY" ]]; then
    echo "Error: Binary file not found: $BINARY" >&2
    exit 1
fi

# Resolve paths before changing how the project is opened.
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
if [[ "$BINARY" != /* ]]; then
    BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"
fi
if [[ "$PROJECT_DIR" != /* ]]; then
    PROJECT_DIR="$PWD/$PROJECT_DIR"
fi

# Create output directory if needed
mkdir -p "$OUTPUT_DIR"

# Generate project name if not specified
if [[ -z "$PROJECT_NAME" ]]; then
    PROJECT_NAME="ghidra_$(basename "$BINARY" | tr '.' '_')_$$"
fi
if [[ "$PERSISTENT" == true && "$PROJECT_NAME_SET" != true ]]; then
    echo "Error: --persistent and --rebuild require --project-name" >&2
    exit 2
fi

PROGRAM_NAME="$(basename "$BINARY")"
PROJECT_FILE="$PROJECT_DIR/$PROJECT_NAME.gpr"
PROJECT_REPOSITORY="$PROJECT_DIR/$PROJECT_NAME.rep"
PROVENANCE_FILE="$PROJECT_DIR/$PROJECT_NAME.provenance.json"
PYTHON_BIN="${PYTHON_BIN:-python3}"
PROVENANCE_SCRIPT="$REPO_ROOT/scripts/analysis_db_provenance.py"

GHIDRA_PROPERTIES="$GHIDRA_HOME/Ghidra/application.properties"
if [[ ! -f "$GHIDRA_PROPERTIES" ]]; then
    echo "Error: Ghidra application properties not found: $GHIDRA_PROPERTIES" >&2
    exit 1
fi
GHIDRA_VERSION="$(
    sed -n 's/^application\.version=//p' "$GHIDRA_PROPERTIES" | head -1
)"
GHIDRA_VERSION="${GHIDRA_VERSION:-unknown}"
PROVENANCE_ARGS=(
    --state "$PROVENANCE_FILE"
    --tool ghidra
    --tool-version "$GHIDRA_VERSION"
    --tool-file "$GHIDRA_PROPERTIES"
    --program "$PROGRAM_NAME"
    --binary "$BINARY"
)

backup_project() {
    local timestamp backup_dir
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    backup_dir="$PROJECT_DIR/backups/$PROJECT_NAME-$timestamp-$$"
    mkdir -p "$backup_dir"
    if [[ -f "$PROJECT_FILE" ]]; then
        mv "$PROJECT_FILE" "$backup_dir/"
    fi
    if [[ -d "$PROJECT_REPOSITORY" ]]; then
        mv "$PROJECT_REPOSITORY" "$backup_dir/"
    fi
    if [[ -f "$PROVENANCE_FILE" ]]; then
        mv "$PROVENANCE_FILE" "$backup_dir/"
    fi
    echo "Backed up previous Ghidra project state to $backup_dir"
}

mkdir -p "$PROJECT_DIR"
if [[ "$REBUILD" == true ]] \
    && [[ -f "$PROJECT_FILE" || -d "$PROJECT_REPOSITORY" || -f "$PROVENANCE_FILE" ]]; then
    backup_project
fi

PROCESS_EXISTING=false
if [[ "$PERSISTENT" == true ]]; then
    if [[ -f "$PROJECT_FILE" && -d "$PROJECT_REPOSITORY" ]]; then
        if ! "$PYTHON_BIN" "$PROVENANCE_SCRIPT" check "${PROVENANCE_ARGS[@]}"; then
            echo "Refusing to reuse Ghidra project $PROJECT_NAME." >&2
            echo "Run this command again with --rebuild for a clean project." >&2
            exit 1
        fi
        PROCESS_EXISTING=true
    elif [[ -f "$PROJECT_FILE" || -d "$PROJECT_REPOSITORY" || -f "$PROVENANCE_FILE" ]]; then
        echo "Error: Incomplete persistent Ghidra project state for $PROJECT_NAME" >&2
        echo "Run this command again with --rebuild to archive it." >&2
        exit 1
    fi
fi

# Build script path including our built-in scripts
BUILTIN_SCRIPTS="$SCRIPT_DIR/ghidra_scripts"
if [[ -n "$SCRIPT_PATH" ]]; then
    FULL_SCRIPT_PATH="$BUILTIN_SCRIPTS;$SCRIPT_PATH"
else
    FULL_SCRIPT_PATH="$BUILTIN_SCRIPTS"
fi

# Build command
if [[ "$PROCESS_EXISTING" == true ]]; then
    echo "Reusing persistent Ghidra project: $PROJECT_DIR/$PROJECT_NAME"
    CMD=("$ANALYZE_HEADLESS" "$PROJECT_DIR" "$PROJECT_NAME" -process "$PROGRAM_NAME")
    for script in "${SCRIPTS[@]}"; do
        if [[ "$(basename "$script")" == "FinalizeAnalysis.java" ]]; then
            # The finalizer runs the required analysis after current maps, so
            # avoid doing analysis once before and once after map application.
            CMD+=(-noanalysis)
            break
        fi
    done
else
    if [[ "$PERSISTENT" == true ]]; then
        echo "Creating persistent Ghidra project: $PROJECT_DIR/$PROJECT_NAME"
    fi
    CMD=("$ANALYZE_HEADLESS" "$PROJECT_DIR" "$PROJECT_NAME" -import "$BINARY")
fi

if [[ "$PERSISTENT" == true && "$PROCESS_EXISTING" != true ]]; then
    export CRIMSON_GHIDRA_FINALIZE_FULL=1
else
    unset CRIMSON_GHIDRA_FINALIZE_FULL
fi

# Add script path
CMD+=(-scriptPath "$FULL_SCRIPT_PATH")

# Add scripts
for i in "${!SCRIPTS[@]}"; do
    script="${SCRIPTS[$i]}"
    CMD+=(-postScript "$script")
    
    # Check if there are args for this script
    for arg_entry in "${SCRIPT_ARGS[@]}"; do
        idx="${arg_entry%%:*}"
        args="${arg_entry#*:}"
        if [[ "$idx" -eq $((i + 1)) ]]; then
            # Append script arguments
            CMD+=($args)
        fi
    done
done

# Add output directory as environment variable for scripts
export GHIDRA_OUTPUT_DIR="$OUTPUT_DIR"

# Add import-only language overrides.
if [[ "$PROCESS_EXISTING" != true && -n "$PROCESSOR" ]]; then
    CMD+=(-processor "$PROCESSOR")
fi

if [[ "$PROCESS_EXISTING" != true && -n "$CSPEC" ]]; then
    CMD+=(-cspec "$CSPEC")
fi

# Add no-analysis flag if specified
if [[ -n "$NO_ANALYSIS" ]]; then
    CMD+=($NO_ANALYSIS)
fi

# Add timeout if specified
if [[ -n "$TIMEOUT" ]]; then
    CMD+=(-analysisTimeoutPerFile "$TIMEOUT")
fi

# Delete project after analysis unless keeping it
if [[ "$KEEP_PROJECT" != true ]]; then
    CMD+=(-deleteProject)
fi

# Keep transient logs out of the structured snapshot directory.
LOG_DIR="${GHIDRA_LOG_DIR:-${TMPDIR:-/tmp}/crimson-ghidra-logs}"
mkdir -p "$LOG_DIR"
PROGRAM_TAG="$(basename "$BINARY" | tr '.' '_')"
LOG_FILE="$LOG_DIR/${PROGRAM_TAG}_analysis.log"
OUTPUT_LOG="$LOG_DIR/${PROGRAM_TAG}_output.log"
CMD+=(-log "$LOG_FILE")

# Run the analysis
if [[ "$VERBOSE" == true ]]; then
    echo "Running: ${CMD[*]}"
fi

"${CMD[@]}" 2>&1 | tee "$OUTPUT_LOG"
exit_code=${PIPESTATUS[0]}

if [[ $exit_code -ne 0 ]]; then
    echo "Analysis failed with exit code: $exit_code" >&2
    echo "Check log file: $LOG_FILE" >&2
    exit "$exit_code"
fi

if [[ "$PERSISTENT" == true ]]; then
    if [[ ! -f "$PROJECT_FILE" || ! -d "$PROJECT_REPOSITORY" ]]; then
        echo "Error: Ghidra completed without a persistent project for $PROJECT_NAME" >&2
        exit 1
    fi
    "$PYTHON_BIN" "$PROVENANCE_SCRIPT" write "${PROVENANCE_ARGS[@]}"
fi

echo ""
echo "Analysis complete. Output files in: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"
