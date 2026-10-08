# Build provenance and inventory

## Verified upstream artifacts

- Base: official `python:3.12-slim-trixie`, multi-architecture manifest digest `sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d`, resolved through Docker Hub registry API.
- 3proxy source: [official 0.9.5 tag](https://github.com/3proxy/3proxy/tree/0.9.5); SHA256 of [codeload tarball](https://codeload.github.com/3proxy/3proxy/tar.gz/refs/tags/0.9.5) = `6f6da51d9bba93231e12acd707bb6cf86a1ab9491dc6dd0c79750cb3641541a3`. Docker build checks the downloaded bytes before extraction/compilation. Hash records observed upstream bytes; it is not a detached publisher signature.
- Python runtime: all direct + transitive versions/artifact SHA256 values in `requirements.txt`, sourced from official PyPI JSON APIs recorded in `dependency-provenance.json`; `pip install --require-hashes` is mandatory.
- `sbom.cdx.json`: CycloneDX 1.5 application/Python/3proxy inventory. The image's Debian package inventory must also be generated after build; this source SBOM is not a complete final-image SBOM.

Linux x86-64 CPython 3.12 wheel resolution/download with `--require-hashes --only-binary=:all:` was verified. Actual Docker compilation/runtime and ARM builds require Linux CI/acceptance. Apt installs still use Debian repositories at build time; the build is dependency-pin hardened, not guaranteed bit-for-bit reproducible. Upgrade system packages with review and record the final image digest.

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

To refresh the base image, resolve the official manifest digest and review OS/Python patch versions, then replace `BASE_IMAGE` and rerun image tests. Publish by image digest, not by mutable `local` tag. CI checks source/unit tests, Bash/Compose, hash installation, image build and Python package inventory. Enable an image scanner/SBOM generator in deployment CI and archive the final image report/digest.

The current CI also generates a full Syft image SBOM (Debian/Python plus explicit source-built 3proxy metadata), scans it with pinned Grype, and archives image ID and hashes. Both actions are commit-pinned and their input contracts checked against upstream. This workflow has to run successfully before treating the image as vulnerability-scanned; the committed source inventory alone is not that evidence.


The original hardened Bookworm candidate was built and scanned, then retained as audit/fix/bookworm-image-* evidence. Its scan reported 100 High/Critical package-CVE matches (47 distinct CVEs), including one available PCRE2 security fix. The current base moves to official Python3.12/Debian Trixie and runs OS security upgrades during build. Scanner severity is not by itself proof of reachability; for example Debian labels CVE-2026-19931 a minor Negotiate-auth connection-reuse issue, while the scanner labels it Critical. This application's probes open fresh curl processes and do not request Negotiate auth. No global ignore or only-fixed suppression is used: unresolved findings keep the High/Critical gate red until component/context-specific triage is reviewed. Debian references: https://security-tracker.debian.org/tracker/CVE-2026-103111 and https://security-tracker.debian.org/tracker/CVE-2026-19931.
