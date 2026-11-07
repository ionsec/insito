# Contributing

INSITO is maintained for incident responders and victims; scope discipline
keeps it auditable. Small patches, one concern at a time.

## Development setup

```console
make vendor   # vendored static libs from source (skipped when artifacts exist)
make static   # ./insito (canonical static build, see README.md)
make test     # synthetic corpus + full recovery verification (tests/run.sh)
```

- Toolchain: gcc/clang + GNU make; LibTomCrypt/LibTomMath are vendored, no
  other dependencies.
- `make test` must stay green and deterministic. The corpus is regenerated
  from seed on every run; no live samples, campaign keys, or victim data are
  ever involved.

## Guidelines

- C99; compile clean under `-Wall -Wextra` (new code, at minimum).
- No new dependencies.
- Behavior changes come with coverage in `tests/run.sh` or
  `tests/insito_selftest.c`.
- The safety contract documented in `README.md` (inputs never modified,
  confirm prompt, report files) is not a suggestion - changes to it need
  explicit justification and updated tests.
- Security issues never go through PRs or issues: see SECURITY.md.

## Pull requests

- One purpose per PR; describe what you ran and paste the relevant output.
- Keep the test corpus synthetic and byte-deterministic.
- By contributing you agree your contribution is MIT-licensed like the rest
  of the project.
