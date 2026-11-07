# INSITO tests

The suite is fully offline and uses **only synthetic, deterministic material**
(`tests/make_corpus.c` regenerates the encrypted decoys on every run; no live
samples, live campaign hashes or victim data are ever involved).

Run with a prebuilt binary:

```console
make static
bash tests/run.sh          # or: make test
```

## What run.sh does

1. **selftest** — compiles and runs `tests/insito_selftest.c` (glibc
   `rand()` TYPE-3 parity check against the tool's clone). The file is
   provided by the project; when it is absent the suite prints `SKIP` and
   continues.
2. **corpus** — compiles and runs `tests/make_corpus.c`, which replays the
   Rhysida locker model with an embedded TEST-ONLY key:

   `srand(seed) -> glibc rand() -> 40 entropy bytes -> one ChaCha20 PRNG
   (start/ready/add_entropy + interleaved malloc draw + 8-byte self-test
   draw) -> per sequence: key[32] + iv[16] draws followed by two
   RSA-4096-OAEP("Rhysida-0.1") wraps (they consume the same live stream) ->
   AES-256-CTR payload (little-endian counter) -> 0x40C-byte trailer
   [keyblob512][len u32=512][ivblob512][len u32=512][type u32=1] -> rename to
   `<name>.rhysida`; ciphertext mtimes stagger 1 s per sequence and lag the
   seed by 600 s, so the default `--window 600` sweep lands on the true clock
   as its first candidate.`

   Plaintext twins are kept in a separate directory for comparison.
3. **recovery** — runs `./insito --scan <ds>` (dry-run must not modify
   anything), then `./insito --datastore <ds> --accept-license --yes`, with an
   isolated `HOME` so the one-time license acceptance is exercised on every
   run. Every restored file is byte-compared (`cmp`) against its pristine
   twin; all encrypted inputs are sha256-compared before/after to prove the
   "inputs never modified" contract; the `recovery-report-*.{txt,json}` files
   in `rhysida_recovered/` must exist. Any mismatch exits non-zero.

## make_corpus interface

```console
tests/make_corpus <expected_plaintext_dir> <datastore_dir> [n_files (1..64, default 12)]
```

The public key comes from the **same** `pubkey_elf.h` the tool is built
against (include via `-I.`), so insito's trailer oracle can reproduce the
wrappings byte-for-byte. Replace it atomically with the tool key if the
embedded defensive key ever rotates — the corpus and the tool must always
agree.

## CI hooks

- `make vendor-clean vendor` rebuilds the vendored static libs from source
  (`vendor/libtomcrypt.a`, `vendor/ltm_desc3.o`, `vendor/libtommath.a`).
- `.github/workflows/build.yml` runs the suite on every push/PR/tag.
- `.github/workflows/security.yml` re-runs it under ASan+UBSan with:

```bash
CC=gcc \
CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all" \
LDFLAGS="-fsanitize=address,undefined" \
INSITO_BIN=./insito-asan \
bash tests/run.sh
```

Environment overrides: `CC`, `CFLAGS`, `LDFLAGS`, `INSITO_BIN`,
`INSITO_TEST_NFILES`, `INSITO_TEST_PUBKEY_DIR`.
