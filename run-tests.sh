#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if ! command -v javac >/dev/null 2>&1; then
    echo "ERROR: javac not found on PATH. Please install JDK 21 or newer." >&2
    exit 1
fi

OUT_DIR="$ROOT_DIR/build"
mkdir -p "$OUT_DIR"
find "$OUT_DIR" -name "*.class" -type f -delete 2>/dev/null || true

TEST_DATA="$OUT_DIR/test-state"
rm -rf "$TEST_DATA"
mkdir -p "$TEST_DATA"

echo "==> compiling"
JAVA_VER=$(javac -version 2>&1 | sed -E 's/.*javac //; s/\..*//' | tr -dc '0-9')
if [ -n "$JAVA_VER" ] && [ "$JAVA_VER" -ge 21 ] 2>/dev/null; then
    RELEASE_FLAG="--release $JAVA_VER"
else
    RELEASE_FLAG="--release 21"
fi

SOURCES=$(find "$ROOT_DIR/src" -name "*.java" -type f)
SOURCES="$SOURCES $ROOT_DIR/tests/Phase1Regression.java $ROOT_DIR/tests/Regression.java $ROOT_DIR/tests/phase2.java $ROOT_DIR/tests/phase3.java $ROOT_DIR/tests/EndToEndWorkflow.java"

javac $RELEASE_FLAG -encoding UTF-8 -d "$OUT_DIR" $SOURCES
echo "compile        PASS"

echo ""
echo "==> running"
FAILURES=0

run_stage() {
    local name="$1"
    local class="$2"
    local output
    if output=$(java "-Dcipher.squad.dataDir=$TEST_DATA" -cp "$OUT_DIR" "$class" 2>&1); then
        if echo "$output" | grep -q "^RESULT: FAIL"; then
            printf "%-14s FAIL\n" "$name"
            echo "$output" | tail -n 20
            FAILURES=$((FAILURES + 1))
        else
            printf "%-14s PASS\n" "$name"
            local summary
            summary=$(echo "$output" | grep -E '^(passed=|OK )' | tail -n 1 || true)
            if [ -n "$summary" ]; then
                echo "               $summary"
            fi
        fi
    else
        printf "%-14s FAIL\n" "$name"
        echo "$output" | tail -n 20
        FAILURES=$((FAILURES + 1))
    fi
}

run_stage "EmailParser" "EmailParser"
run_stage "Enrich" "Enrich"
run_stage "Attribution" "Attribution"
run_stage "Correlate" "Correlate"
run_stage "Phase1Regression" "Phase1Regression"
run_stage "Regression" "Regression"
run_stage "phase2" "phase2"
run_stage "phase3" "phase3"
run_stage "EndToEndWorkflow" "EndToEndWorkflow"

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "ALL STAGES PASSED (9 stages)"
    rm -rf "$TEST_DATA"
    exit 0
else
    echo "FAILED: $FAILURES stage(s) failed."
    exit 1
fi
