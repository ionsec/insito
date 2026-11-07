# Security Policy

## Supported versions

| Build | Supported |
| --- | --- |
| latest release (see [RELEASE_URL]) | yes |
| `main` branch | best effort |
| older releases and forks | no - rebuild from source |

## Reporting a vulnerability

Report privately; do not open public issues for security problems.

- Email: `info@ionsec.io`, subject prefix `INSITO-SECURITY`. 24/7 incident
  intake: [IONSEC_URL]/services/emergency-ir
- Contact channels and response SLAs: [IONSEC_URL]/security

Include: affected version or commit, the build command used, platform
(ESXi/Linux), a reproduction, and the recovery report file if one was
produced. Acknowledgement within 3 business days; coordinated disclosure with
a 90-day window.

## Encrypted disclosure

If the report is sensitive, encrypt it: request the project PGP key published
at [IONSEC_URL]/pgp.txt (fingerprint published on the same page), encrypt to
that key and send to the address above with the subject
`INSITO-SECURITY (ENCRYPTED)`. Never post encrypted blobs or raw evidence in
GitHub issues or PRs.

## Verifying release artifacts (signed SHA256)

Release assets ship with `SHA256SUMS` and a detached signature
(`SHA256SUMS.gpg`) made with the IONSEC.IO release key:

```console
sha256sum -c SHA256SUMS
gpg --import ionsec-release.asc        # from [IONSEC_URL]/pgp.txt
gpg --verify SHA256SUMS.gpg SHA256SUMS
```

Signatures are only meaningful in combination with the checksums: verify the
hash of the downloaded binary first, then verify the signature over the
checksums file. Release key fingerprints are published on [IONSEC_URL].
A failed verification is a security report - stop using the artifact and
contact us privately.

## Test material policy

Do not attach live malware samples, campaign artifacts, keys, or real victim
data to issues, PRs, or commits. The bundled test corpus is synthetic,
deterministic and regeneration-based (`tests/make_corpus.c`); it must stay
that way.
