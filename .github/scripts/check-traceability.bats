#!/usr/bin/env bats

# Self-tests for check-traceability.sh.
# Each test feeds a fixture pair (PR body + changed-files list) to the
# script in --dry-run mode and asserts the exit code and output. The
# fixtures cover all five paths of the gate (AC6 a-e) plus an invalid
# field value.

setup() {
  SCRIPT_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)"
  SCRIPT="$SCRIPT_DIR/check-traceability.sh"
  FIXTURES="$SCRIPT_DIR/fixtures"
}

run_with() {
  local body_fixture="$1"
  local files_fixture="$2"
  PR_BODY_FILE="$FIXTURES/$body_fixture" \
    CHANGED_FILES_FILE="$FIXTURES/$files_fixture" \
    run "$SCRIPT" --dry-run
}

@test "AC6a: yes path with matrix change passes" {
  run_with yes-with-matrix.body yes-with-matrix.files
  [ "$status" -eq 0 ]
  [[ "$output" == *"Traceability gate passed"* ]]
}

@test "AC6b: yes path without matrix change fails" {
  run_with yes-without-matrix.body yes-without-matrix.files
  [ "$status" -ne 0 ]
  [[ "$output" == *"Traceability gate failed"* ]]
  [[ "$output" == *"docs/traceability.md is not in the changed-files list"* ]]
}

@test "AC6c: no path with non-empty rationale passes" {
  run_with no-with-rationale.body no-with-rationale.files
  [ "$status" -eq 0 ]
  [[ "$output" == *"Traceability gate passed"* ]]
}

@test "AC6d: no path with HTML-comment-only rationale fails" {
  run_with no-empty-rationale.body no-empty-rationale.files
  [ "$status" -ne 0 ]
  [[ "$output" == *"Traceability gate failed"* ]]
  [[ "$output" == *"rationale"* ]]
}

@test "AC6e: missing traceability_updated field fails" {
  run_with missing-field.body missing-field.files
  [ "$status" -ne 0 ]
  [[ "$output" == *"Traceability gate failed"* ]]
  [[ "$output" == *"field missing"* ]]
}

@test "Invalid traceability_updated value fails" {
  run_with invalid-value.body invalid-value.files
  [ "$status" -ne 0 ]
  [[ "$output" == *"Traceability gate failed"* ]]
  [[ "$output" == *"must be exactly 'yes' or 'no'"* ]]
}
