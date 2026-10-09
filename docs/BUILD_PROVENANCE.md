# Build provenance and inventory

## Verified upstream artifacts

- Base: official `python:3.12-slim-trixie`, multi-architecture manifest digest `sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d`, resolved through Docker Hub registry API.
- 3proxy source: [official 0.9.6 tag](https://github.com/3proxy/3proxy/tree/0.9.6); SHA256 of [codeload tarball](https://codeload.github.com/3proxy/3proxy/tar.gz/refs/tags/0.9.6) = `5645111fb146faaaf260c27f0e07e510e8530a7e8a18369474cc8abbedbc9c9a`. Docker build checks the downloaded bytes before extraction/compilation. Hash records observed upstream bytes; it is not a detached publisher signature.
- Python runtime: all direct + transitive versions/artifact SHA256 values in `requirements.txt`, sourced from official PyPI JSON APIs recorded in `dependency-provenance.json`; `pip install --require-hashes` is mandatory.
- `sbom.cdx.json`: CycloneDX 1.5 application/Python/3proxy inventory. The image's Debian package inventory must also be generated after build; this source SBOM is not a complete final-image SBOM.

Linux x86-64 CPython 3.12 wheel resolution/download with `--require-hashes --only-binary=:all:` was verified. The release workflow targets `linux/amd64`, `linux/arm64` and `linux/arm/v7`; each image must compile and pass runtime tests on its target platform. `amd64`/`arm64` use native runners, while `arm/v7` runs with QEMU emulation. These are workflow targets, not evidence that all three registry variants have already been published. Apt installs still use Debian repositories at build time; the build is dependency-pin hardened, not guaranteed bit-for-bit reproducible. Upgrade system packages with review and record the final image digest.

Native `amd64`/`arm64` integration exercises the production engine ownership checks. The ARMv7 QEMU job instead uses a separate direct binary probe for config/authentication/source-binding/listener/lifecycle behavior plus the image's worker/dashboard/credential tests. Host `/proc/PID/exe` may identify the QEMU emulator, so that job does not claim production ownership verification or native ARMv7 hardware acceptance. Do not weaken the production ownership guard to make emulation pass.

## Updating

```bash
python3 scripts/lock_dependencies.py             # preserve direct dependency versions
python3 scripts/lock_dependencies.py --upgrade   # explicitly review new direct versions
python3 -m pip download --require-hashes --only-binary=:all: --platform manylinux2014_x86_64 --python-version 3.12 --implementation cp --abi cp312 -r requirements.txt -d audit/fix/wheels
node tests/test_frontend.js
python3 -m unittest discover -s tests -v
docker compose -f docker-compose.yml -f docker-compose.build.yml build
```

Review current [3proxy releases/security](https://github.com/3proxy/3proxy/releases) before deployment. A major 3proxy upgrade requires configuration parser, foreground lifecycle, ACL, authentication and source-binding regression tests; it is not silently substituted for the original engine version in this patch.

To refresh the base image, resolve the official manifest digest and review OS/Python patch versions, then replace `BASE_IMAGE` and rerun image tests. Publish by image digest, not by mutable `local` tag. CI checks source/unit tests, Bash/Compose, hash installation, image build and Python package inventory, then generates/scans the full-image SBOM and archives the report/digest for each architecture.

The CI design generates a full Syft image SBOM for each architecture (Debian/Python plus explicit source-built 3proxy metadata), scans it with pinned Grype, and archives image ID and hashes. Both actions are commit-pinned and their input contracts checked against upstream. Full vulnerability JSON is produced without an `only-fixed` filter; a separate gate rejects High/Critical findings with non-empty scanner fix-version lists, including inconsistent fix-state metadata. Malformed reports fail closed. Findings without fixes remain in the archived full report, not suppressed or ignored. This workflow has to run successfully before treating an image as vulnerability-scanned; the committed source inventory alone is not that evidence.

Architecture jobs publish only commit/architecture tags after their unit, runtime and vulnerability gates succeed, then pull and test their exact registry digest. The final publish job requires all three jobs and verifies release-record commit/platform/digest correspondence before combining the tested digests into a shared manifest. It publishes `latest`/commit/version tags without rebuilding and verifies platform membership plus pulls for each architecture; import/maxconn checks have already run against the individual digests. See [container release](CONTAINER_RELEASE.md) for the designed pipeline and registry access checks.


The original hardened Bookworm candidate was built and scanned, then retained as audit/fix/bookworm-image-* evidence. Its scan reported 100 High/Critical package-CVE matches (47 distinct CVEs), including one available PCRE2 security fix. The current base moves to official Python3.12/Debian Trixie and runs OS security upgrades during build. Scanner severity is not by itself proof of reachability; for example Debian labels CVE-2026-19931 a minor Negotiate-auth connection-reuse issue, while the scanner labels it Critical. This application's probes open fresh curl processes and do not request Negotiate auth. The approved release gate blocks fixable High/Critical findings only; full reports retain unresolved findings for subsequent patching and context review. No global CVE ignore list is used. Debian references: https://security-tracker.debian.org/tracker/CVE-2026-103111 and https://security-tracker.debian.org/tracker/CVE-2026-19931.
