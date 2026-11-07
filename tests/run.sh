#!/usr/bin/env bash
# INSITO test suite: builds the SYNTHETIC Rhysida-model corpus, then verifies
# recovery end-to-end (--scan dry-run -> --datastore restore -> byte compare).
# The corpus is deterministic and synthetic; no live samples are used anywhere.
#
# Interfaces:
#   tests/make_corpus <expected_plaintext_dir> <datastore_dir> [n_files]
#     -> writes plaintext decoys into  <expected_plaintext_dir>
#     -> writes the encrypted <name>.rhysida twins into <datastore_dir>
#
# Environment overrides (used by CI and by .github/workflows/security.yml):
#   CC / CFLAGS / LDFLAGS   compiler and flags for the helper binaries
#   INSITO_BIN              insito binary under test (default ./insito)
#   INSITO_TEST_NFILES      corpus size (default 12, range 1..64)
#   INSITO_TEST_PUBKEY_DIR  optional extra -I for tests/make_corpus.c (lets a
#                           scratch build supply its own TEST-ONLY key header)
#
# tests/insito_selftest.c (glibc rand TYPE-3 parity check) is provided by the
# project; when it is absent the suite prints SKIP for that step and continues.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CC="${CC:-cc}"
CFLAGS="${CFLAGS:--O2}"
LDFLAGS="${LDFLAGS:-}"
INSITO_BIN="${INSITO_BIN:-./insito}"
N_FILES="${INSITO_TEST_NFILES:-12}"
case "$N_FILES" in (*[!0-9]*|'') echo "FAIL: INSITO_TEST_NFILES must be numeric" >&2; exit 1;; esac
if [ "$N_FILES" -lt 1 ] || [ "$N_FILES" -gt 64 ]; then echo "FAIL: INSITO_TEST_NFILES out of range 1..64" >&2; exit 1; fi

# resolve INSITO_BIN to an absolute path so runs stay cwd-independent
case "$INSITO_BIN" in
  /*) ;;
  *) INSITO_BIN="${REPO_ROOT}/${INSITO_BIN#./}" ;;
esac

DEFS="-DUSE_LTM -DLTM_DESC"
LTC_INC="-Ivendor/libtomcrypt/src/headers"
PKG_INC="${LTC_INC} -Ivendor/libtommath"
[ -n "${INSITO_TEST_PUBKEY_DIR:-}" ] && PKG_INC="-I${INSITO_TEST_PUBKEY_DIR} ${PKG_INC}"
PKG_INC="${PKG_INC} -I."
VENDOR_LIBS="vendor/argchk_stub.o vendor/ltm_desc3.o vendor/libtomcrypt.a vendor/libtommath.a"
[ -f vendor/argchk_stub.o ] || "$CC" $CFLAGS -c vendor/argchk_stub.c -o vendor/argchk_stub.o

pass() { printf '[PASS] %s\n' "$*"; }
skip() { printf '[SKIP] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
run()  { printf '[RUN ] %s\n' "$*" >&2; }

# --------------------------------------------------------------- prerequisites
command -v "$CC" >/dev/null 2>&1 || fail "compiler '$CC' not found"
[ -f tests/make_corpus.c ] || fail "tests/make_corpus.c missing"
for lib in $VENDOR_LIBS; do
  [ -f "$lib" ] || fail "missing $lib (run 'make vendor' first)"
done

TEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/insito_test.XXXXXX")"
trap 'rm -rf "$TEST_TMP"' EXIT
PRISTINE="$TEST_TMP/corpus-expected"
DS="$TEST_TMP/corpus-testsynthetic"
mkdir -p "$PRISTINE" "$DS"

# ------------------------------------------------------ a) insito_selftest.c
if [ -f tests/insito_selftest.c ]; then
  run "compiling tests/insito_selftest.c"
  # shellcheck disable=SC2086
  "$CC" $CFLAGS -Wall -Wextra $DEFS $PKG_INC tests/insito_selftest.c $LDFLAGS $VENDOR_LIBS \
    -o "$TEST_TMP/insito_selftest" \
    || fail "compiling tests/insito_selftest.c failed"
  "$TEST_TMP/insito_selftest" || fail "tests/insito_selftest.c failed"
  pass "insito_selftest (glibc rand parity)"
else
  skip "tests/insito_selftest.c not present (provided by the project)"
fi

# --------------------------------------------------------- b) synthetic corpus
run "compiling tests/make_corpus.c"
# shellcheck disable=SC2086
"$CC" $CFLAGS -Wall -Wextra $DEFS $PKG_INC tests/make_corpus.c $LDFLAGS $VENDOR_LIBS \
  -o "$TEST_TMP/make_corpus" \
  || fail "compiling tests/make_corpus.c failed"
run "generating synthetic corpus ($N_FILES decoys, TEST-ONLY embedded key)"
"$TEST_TMP/make_corpus" "$PRISTINE" "$DS" "$N_FILES" || fail "corpus generation failed"

enc_count() { find "$DS" -type f -name '*.rhysida' | wc -l | tr -d ' '; }
[ "$(enc_count)" -eq "$N_FILES" ] || fail "expected $N_FILES .rhysida files, got $(enc_count)"
[ "$(find "$PRISTINE" -type f | wc -l | tr -d ' ')" -eq "$N_FILES" ] \
  || fail "expected $N_FILES plaintext decoys in $PRISTINE"

ciphertext_state() { ( cd "$DS" && find . -type f -name '*.rhysida' -print0 | sort -z | xargs -0 sha256sum ); }
ciphertext_state > "$TEST_TMP/ct.sha.before"

# ------------------------------------------------------------- c) scan dry-run
# fresh isolated HOME => the one-time license acceptance runs, then the confirm
# gate never fires for --scan (decrypt only). Nothing may be written anywhere.
run "${INSITO_BIN##*/} --scan $DS (dry-run)"
mkdir -p "$TEST_TMP/home-scan"
HOME="$TEST_TMP/home-scan" "$INSITO_BIN" --scan "$DS" --accept-license >"$TEST_TMP/scan.log" 2>&1 \
  || { tail -20 "$TEST_TMP/scan.log" >&2; fail "--scan exited non-zero"; }
ciphertext_state > "$TEST_TMP/ct.sha.scan"
cmp -s "$TEST_TMP/ct.sha.before" "$TEST_TMP/ct.sha.scan" || fail "--scan modified encrypted inputs"
pass "--scan dry-run left every encrypted input untouched"

# ----------------------------------------------------------- d) recovery run
# --accept-license --yes = explicit non-interactive override of the gates
# (README safety table); isolated HOME exercises the fresh-acceptance path.
run "${INSITO_BIN##*/} --datastore $DS --accept-license --yes"
mkdir -p "$TEST_TMP/home-run"
HOME="$TEST_TMP/home-run" "$INSITO_BIN" --datastore "$DS" --accept-license --yes \
  >"$TEST_TMP/recover.log" 2>&1 \
  || { tail -30 "$TEST_TMP/recover.log" >&2; fail "insito exited non-zero"; }

ciphertext_state > "$TEST_TMP/ct.sha.after"
cmp -s "$TEST_TMP/ct.sha.before" "$TEST_TMP/ct.sha.after" \
  || fail "encrypted inputs were modified by insito (contract: inputs never modified)"

OUT="$DS/rhysida_recovered"
[ -d "$OUT" ] || { ls -la "$DS" >&2 2>/dev/null || true; fail "restore directory $OUT not created"; }

restored_count=0
for orig in "$PRISTINE"/*; do
  name="$(basename "$orig")"
  if [ ! -f "$OUT/$name" ]; then
    { printf 'restored files present in %s:\n' "$OUT"; ls "$OUT"; } >&2
    fail "no restored output found for $name"
  fi
  cmp -s "$orig" "$OUT/$name" || fail "restored $name differs from expected plaintext"
  restored_count=$((restored_count + 1))
done
[ "$restored_count" -eq "$N_FILES" ] || fail "restored $restored_count/$N_FILES files"

report_txt="$(find "$OUT" -maxdepth 1 -type f -name 'recovery-report-*.txt' | wc -l | tr -d ' ')"
report_json="$(find "$OUT" -maxdepth 1 -type f -name 'recovery-report-*.json' | wc -l | tr -d ' ')"
if [ "$report_txt" -lt 1 ] || [ "$report_json" -lt 1 ]; then
  ls "$OUT" >&2
  fail "recovery report (txt/json) missing in $OUT"
fi

printf '[PASS] %d/%d files restored byte-identical; encrypted inputs unmodified; %s txt + %s json recovery report(s)\n' \
  "$restored_count" "$N_FILES" "$report_txt" "$report_json"
exit 0
