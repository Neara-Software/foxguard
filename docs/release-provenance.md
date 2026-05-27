# Release provenance

foxguard publishes prebuilt binaries through GitHub Releases. Each release
contains platform binaries plus `checksums.txt`.

## What is published

The release workflow publishes GitHub artifact attestations for:

- every platform binary listed in `checksums.txt`
- the `checksums.txt` manifest itself

The binary attestations are generated from the checksum manifest, so each
attestation subject is the exact SHA-256 digest users download. The checksum
manifest is attested separately so users can verify both the binary and the
integrity manifest.

## What installers verify

The GitHub Action, npm wrapper, and `install.sh` download `checksums.txt` and
verify the selected binary's SHA-256 digest before executing or caching it. A
missing checksum, failed checksum download, missing digest, or digest mismatch
is a hard install failure.

Those installers do not require provenance verification at runtime. Provenance
verification needs GitHub's attestation service and a networked verifier such as
the GitHub CLI, so it is an explicit user or CI policy step.

## Manual verification

Download the release asset and checksum manifest, then verify them with the
GitHub CLI:

```sh
gh attestation verify foxguard-linux-x86_64 --repo 0sec-labs/foxguard
gh attestation verify checksums.txt --repo 0sec-labs/foxguard
```

After provenance verification succeeds, verify the local digest:

```sh
sha256sum -c checksums.txt --ignore-missing
```

On macOS:

```sh
grep '  foxguard-macos-aarch64$' checksums.txt
shasum -a 256 foxguard-macos-aarch64
```

## Failure modes

- If `checksums.txt` is missing or does not contain the selected binary, treat
  the install as untrusted.
- If the binary digest does not match `checksums.txt`, do not use the binary.
- If `gh attestation verify` fails or no attestation is found, treat the binary
  as lacking release provenance even if its checksum matches.
- If GitHub artifact attestations are unavailable for the repository or
  organization, the release workflow fails before publishing the GitHub Release.

## Trust model

Checksums protect against accidental corruption and simple mirror tampering.
GitHub artifact attestations bind a downloaded digest to the `0sec-labs/foxguard`
repository, the release workflow identity, and the tag build that produced it.

This does not prove the source code is bug-free and does not protect against a
compromised repository, compromised release workflow, or compromised GitHub
identity. It gives users evidence that a release asset came from the expected
GitHub Actions build path.
