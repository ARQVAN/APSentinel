#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

CC=${CC:-cc}
BIN="$TMP/rogue"

PASS=0
FAIL=0

pass() {
  printf 'PASS: %s\n' "$1"
  PASS=$((PASS + 1))
}

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  FAIL=$((FAIL + 1))
  exit 1
}

assert_contains() {
  output=$1
  expected=$2
  description=$3

  if printf '%s\n' "$output" | grep -Fq -- "$expected"; then
    pass "$description"
  else
    printf '%s\n' "$output" >&2
    fail "$description (missing: $expected)"
  fi
}

make_dataset() {
  file=$1
  address=$2
  count=$3
  rssi=$4
  manufacturer_bytes=$5
  service_count=$6
  service_bytes=$7
  manufacturer_hex=$8
  service_hex=$9

  printf 'timestamp\taddress\trssi\tmanufacturer_bytes\tservice_count\tservice_data_bytes\tmanufacturer_hex\tservice_data_hex\n' >"$file"

  i=1
  while [ "$i" -le "$count" ]; do
    printf '1000.%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$i" "$address" "$rssi" "$manufacturer_bytes" \
      "$service_count" "$service_bytes" \
      "$manufacturer_hex" "$service_hex" >>"$file"
    i=$((i + 1))
  done
}

make_legacy_dataset() {
  file=$1
  address=$2
  count=$3

  printf 'timestamp\taddress\trssi\tmanufacturer_bytes\tservice_count\tservice_data_bytes\n' >"$file"

  i=1
  while [ "$i" -le "$count" ]; do
    printf '1000.%s\t%s\t-50\t0\t1\t4\n' \
      "$i" "$address" >>"$file"
    i=$((i + 1))
  done
}

printf '%s\n' '=== RogueNet regression tests ==='

# Compile the exact source under test.
if ! "$CC" -std=c11 -D_POSIX_C_SOURCE=200809L \
  -Wall -Wextra -Wpedantic -O2 \
  "$ROOT/src/rogue.c" -lm -o "$BIN"; then
  fail "compile src/rogue.c"
fi
pass "compile src/rogue.c"

A='AA:BB:CC:DD:EE:01'
B='AA:BB:CC:DD:EE:02'
UUID='0000fcf1-0000-1000-8000-00805f9b34fb'

# Baseline: 20 stable observations.
make_dataset "$TMP/baseline.tsv" "$A" 20 \
  -50 0 1 4 '' "$UUID:aaaa"

# Matching observations should produce no deviations.
make_dataset "$TMP/matching.tsv" "$A" 20 \
  -50 0 1 4 '' "$UUID:aaaa"

# Changed behavior and changed payload.
make_dataset "$TMP/changed.tsv" "$A" 20 \
  -80 12 4 20 '1234:deadbeef' "$UUID:bbbb"

# A single observation must not qualify for a baseline.
make_dataset "$TMP/insufficient.tsv" "$A" 1 \
  -50 0 1 4 '' "$UUID:aaaa"

# Old six-column format: fingerprint features remain available.
make_legacy_dataset "$TMP/legacy.tsv" "$A" 20

# Two addresses sharing one exact service-data signature.
make_dataset "$TMP/shared.tsv" "$A" 20 \
  -50 0 1 4 '' "$UUID:shared"
make_dataset "$TMP/shared-part.tsv" "$B" 20 \
  -55 0 1 4 '' "$UUID:shared"
tail -n +2 "$TMP/shared-part.tsv" >>"$TMP/shared.tsv"

# 1. Summary.
out=$("$BIN" summary "$TMP/matching.tsv" 2>&1) ||
  fail "summary command"
assert_contains "$out" "Loaded 20 observations" \
  "summary loads all observations"
assert_contains "$out" "Distinct addresses: 1" \
  "summary counts distinct addresses"

# 2. Create fingerprint and payload baselines.
out=$("$BIN" baseline "$TMP/baseline.tsv" "$A" \
  "$TMP/fingerprint.tsv" 2>&1) ||
  fail "fingerprint baseline"
assert_contains "$out" "Baseline saved to" \
  "fingerprint baseline is created"

out=$("$BIN" payload-baseline "$TMP/baseline.tsv" "$A" \
  "$TMP/payload.tsv" 2>&1) ||
  fail "payload baseline"
assert_contains "$out" "Unique payload signatures: 1" \
  "payload baseline contains expected signature"

# Reject malformed v2 headers.
sed '1s/$/0/' "$TMP/payload.tsv" >"$TMP/malformed-payload.tsv"

if "$BIN" payload-check "$TMP/matching.tsv" "$A" \
  "$TMP/malformed-payload.tsv" >"$TMP/malformed.out" 2>&1; then
  status=0
else
  status=$?
fi

[ "$status" -eq 2 ] ||
  fail "malformed payload baseline header returned $status instead of 2"
pass "malformed payload baseline header is rejected"

# Duplicate payload tokens must count only once per observation.
make_dataset "$TMP/duplicate.tsv" "$A" 20 -50 0 1 4 '' \
  "$UUID:aaaa;$UUID:aaaa"

out=$("$BIN" payload-baseline "$TMP/duplicate.tsv" "$A" \
  "$TMP/duplicate-payload.tsv" 2>&1) ||
  fail "duplicate-token payload baseline"

assert_contains "$out" "Unique payload signatures: 1" \
  "duplicate tokens produce one unique signature"

if grep -Fq "$(printf 'service_data_hex\t%s:aaaa\t20' "$UUID")" \
  "$TMP/duplicate-payload.tsv"; then
  pass "duplicate payload tokens count once per observation"
else
  cat "$TMP/duplicate-payload.tsv" >&2
  fail "duplicate payload token count was not 20"
fi

# Duplicate sample-count metadata must be rejected.
awk '
  NR == 3 { print; print; next }
  { print }
' "$TMP/payload.tsv" >"$TMP/duplicate-samples.tsv"

if "$BIN" payload-check "$TMP/matching.tsv" "$A" \
  "$TMP/duplicate-samples.tsv" >"$TMP/duplicate-samples.out" 2>&1; then
  status=0
else
  status=$?
fi

[ "$status" -eq 2 ] ||
  fail "duplicate sample metadata returned $status instead of 2"
pass "duplicate sample-count metadata is rejected"

# 3. Matching input.
out=$("$BIN" check "$TMP/matching.tsv" "$A" \
  "$TMP/fingerprint.tsv" "$TMP/payload.tsv" 2>&1) ||
  fail "matching check"
assert_contains "$out" "NO OBSERVED DEVIATIONS" \
  "matching fingerprint and payload pass"
assert_contains "$out" "not proof of impersonation" \
  "combined assessment includes its caveat"

# 3a. Payload-check exit statuses.
# Matching data must exit 0.
if out=$("$BIN" payload-check "$TMP/matching.tsv" "$A" \
  "$TMP/payload.tsv" 2>&1); then
  status=0
else
  status=$?
fi

[ "$status" -eq 0 ] ||
  fail "matching payload-check returned $status instead of 0"
pass "matching payload-check exits 0"

# Remove the payload from half the observations.
# The signature remains present, but its frequency drops from 100% to 50%.
awk -F '\t' 'BEGIN { OFS = "\t" }
  NR == 1 { print; next }
  NR % 2 == 0 { $8 = "" }
  { print }
' "$TMP/matching.tsv" >"$TMP/frequency.tsv"

if out=$("$BIN" payload-check "$TMP/frequency.tsv" "$A" \
  "$TMP/payload.tsv" 2>&1); then
  status=0
else
  status=$?
fi

[ "$status" -eq 1 ] ||
  fail "frequency-only payload change returned $status instead of 1"
assert_contains "$out" "Frequency changes: 1" \
  "frequency-only payload change is detected"
pass "frequency-only payload-check exits 1"

# An invalid baseline must return the error exit code 2.
if "$BIN" payload-check "$TMP/matching.tsv" "$A" \
  "$TMP/missing-payload.tsv" >"$TMP/payload-error.out" 2>&1; then
  status=0
else
  status=$?
fi

[ "$status" -eq 2 ] ||
  fail "invalid payload comparison returned $status instead of 2"
pass "invalid payload comparison exits 2"

# Combined check must report frequency-only payload deviations.
out=$("$BIN" check "$TMP/frequency.tsv" "$A" \
  "$TMP/fingerprint.tsv" "$TMP/payload.tsv" 2>&1) ||
  fail "frequency-only combined check"

assert_contains "$out" "PAYLOAD DEVIATION" \
  "combined check detects frequency-only payload changes"

# 4. Changed input.
out=$("$BIN" check "$TMP/changed.tsv" "$A" \
  "$TMP/fingerprint.tsv" "$TMP/payload.tsv" 2>&1) ||
  fail "changed-input check"
assert_contains "$out" "BEHAVIORAL AND PAYLOAD DEVIATIONS" \
  "behavioral and payload changes are detected"
assert_contains "$out" "NEW" \
  "new payload signature is reported"
assert_contains "$out" "MISSING" \
  "missing payload signature is reported"
assert_contains "$out" "not proof of impersonation" \
  "deviation assessment includes its caveat"

# 5. Insufficient samples must be rejected.
if "$BIN" baseline "$TMP/insufficient.tsv" "$A" \
  "$TMP/should-not-exist.tsv" >"$TMP/insufficient.out" 2>&1; then
  fail "baseline accepted insufficient samples"
fi
assert_contains "$(cat "$TMP/insufficient.out")" \
  "need at least 20" \
  "fingerprint baseline rejects insufficient samples"

if "$BIN" payload-baseline "$TMP/insufficient.tsv" "$A" \
  "$TMP/should-not-exist-payload.tsv" \
  >"$TMP/payload-insufficient.out" 2>&1; then
  fail "payload baseline accepted insufficient samples"
fi
assert_contains "$(cat "$TMP/payload-insufficient.out")" \
  "at least 20 required" \
  "payload baseline rejects insufficient samples"

# 6. Legacy six-column TSV.
out=$("$BIN" baseline "$TMP/legacy.tsv" "$A" \
  "$TMP/legacy-baseline.tsv" 2>&1) ||
  fail "legacy fingerprint baseline"
assert_contains "$out" "Baseline saved to" \
  "legacy TSV supports fingerprint baselines"

if "$BIN" payload-baseline "$TMP/legacy.tsv" "$A" \
  "$TMP/legacy-payload.tsv" >"$TMP/legacy.out" 2>&1; then
  fail "payload baseline accepted legacy TSV without payload columns"
fi
assert_contains "$(cat "$TMP/legacy.out")" \
  "Payload data unavailable" \
  "legacy TSV is rejected for payload analysis"

# 7. Shared payload correlation.
out=$("$BIN" correlate "$TMP/shared.tsv" 2>&1) ||
  fail "payload correlation"
assert_contains "$out" "Shared payloads found: 1" \
  "shared payload is found across two addresses"
assert_contains "$out" "device identity is unconfirmed" \
  "correlation does not claim device identity"

printf '\nResults: %s passed, %s failed\n' "$PASS" "$FAIL"
printf '%s\n' 'All regression tests passed.'
