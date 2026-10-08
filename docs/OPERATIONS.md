# Operational checklist

## State and recovery

- Persistent worker state lives only in named volume `proxy-data`; dashboard does not need a data volume. Preserve this volume across rebuilds.
- Back up after successful operations and before topology/prefix/credential migration. A backup of state/config may contain proxy passwords and Telegram token; store it encrypted with operator-only access and test restore in a lab.
- `docker compose down` retains named volumes; `docker compose down -v` destroys state. Do not use `-v` for routine upgrades.
- Stable admin/service/session secrets live in host `secrets/`, never in Compose inline environment defaults or source commits. Rotate service token on both containers together, restart them and verify authenticated IPC/API. Rotate session key intentionally to invalidate sessions.
- Service requests use Bearer token; browser mutations use CSRF plus Idempotency-Key. Never blindly retry an uncertain mutating result: inspect state/revision/pending operation first. Same idempotency key is for the **same input** only.
- UI success means worker verified operation. If rollback/cleanup remains pending, review worker last_error/event log before another mutation.
- Every proxy record retains its interface, network prefix, actual alias prefix (`/128` for new aliases), topology mode and routed prefix. Global defaults do not redefine an existing group's topology. LAN prefix renewal is checked for each group without renumbering routed-prefix siblings.
- Kernel address creation is exclusive for newly generated aliases. A pre-existing address is not adopted. If a crash interrupts the boundary between kernel creation and persisted confirmation, health exposes `uncertain_addresses` rather than guessing ownership; no automatic deletion occurs. Complete pending recovery, compare operation/address/interface with kernel snapshot and journal, then acknowledge the matching record through authenticated `POST /api/ownership/resolve` with `{operation_id,address,interface,acknowledge_unmanaged:true}`. That endpoint only clears uncertainty metadata and leaves the NIC untouched. Keep a record of the operator decision; see [Linux acceptance](LINUX_ACCEPTANCE.md#6-crash-ownership-review).

## Migration from the original single-container version

1. Stop the original deployment; copy its `data` directory and original deployment/source files into an operator-only backup.
2. Use a clean deployment initially to validate topology, credentials, ports and egress. Do not run original watchdog and new worker against the same NIC/state.
3. Review the new worker's explicit legacy import support before migrating JSON state. Do not manually infer ownership of existing `/128` addresses: existing IPs do not become app-owned merely because they share a prefix.
4. Generate a small validated set with distinct free ports, run acceptance and then migrate clients. Keep backup recoverable until route/source/ACL tests pass.

## Monitoring

Track desired_state vs actual ready state, expected/running instance count, last_error, pending operations, owned IPv6 cleanup backlog, source probe failures, DAD/prefix lifetime, DNS errors, FD/RSS/CPU and latency/error rates. A dashboard process being alive is not proof proxy egress works. Healthchecks are local container availability checks; operator acceptance validates actual router/ISP behavior.

Authenticated `GET /api/proxy/health` supplies `metrics.worker` (RSS bytes/FD count), `metrics.proxy_children` (RSS bytes/FD count/process count) and `metrics.ndp` (neighbor count/states by managed interface). Missing observations are `null` with diagnostic errors, not invented zeros. Host neighbor entries do not measure the upstream router's entire NDP table. Benchmark stores credential-redacted before/after snapshots; use host/router monitoring for peaks and CPU history.

The benchmark matrix defaults to25/50/100/200 participating listener records, never changes deployment state and caps total traffic concurrency across listeners. To compare actual deployed-count capacity, run a separate validated deployment at each count and match health totals. Protocol input is explicit (`http://` or `socks5h://`); dual has two services. Preserve the raw reports with environment/topology/MTU/NIC/router versions, mode settings and fault-injection outcomes before deciding an instance sharding limit.

## Image provenance and vulnerability gate

The CI workflow builds the pinned source/base image, creates a Syft CycloneDX SBOM of Debian and Python image packages, appends the source-built 3proxy version/source SHA256/actual image binary SHA256, and scans that full SBOM with Grype. Image ID, lockfile/Dockerfile/SBOM hashes, inventory and vulnerability JSON are archived together. The committed dependency-only SBOM is not proof a runtime image passed scanning.

Actions use immutable commit SHAs; scanner versions are fixed explicitly. The vulnerability database remains current: scan/download/database errors fail the job, and High/Critical findings fail even without available fixes. A passed scan is bounded by scanner catalog coverage and that database/time, not an assertion of no vulnerabilities; source review and Linux acceptance remain separate gates. Source-built 3proxy metadata is explicit because a stripped standalone binary may not be recognized automatically by a package cataloger.

Review security reports on every dependency/base/source update. Update pins through an auditable change, rebuild, preserve the new image evidence, and repeat acceptance before promotion. No unrestricted Docker socket or production data volume is mounted into scanner workloads; the workflow scans only its build output. Tool contracts: [Anchore SBOM action](https://github.com/anchore/sbom-action), [Anchore scan action](https://github.com/anchore/scan-action), [Grype](https://github.com/anchore/grype).

## Host isolation boundary

Host network intentionally shares the Linux network namespace: the NET_ADMIN worker can change host NIC addresses/routes even without privileged mode. Keep that capability out of dashboard, keep management loopback/TLS/ACL controlled, and never mount Docker socket or host filesystem broadly. See [Docker host network](https://docs.docker.com/engine/network/drivers/host/) and [runtime capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities).

The optional dnsmasq uses port5353 and may conflict with an existing host service. Disable it by default; startup child failure causes a controlled container restart rather than silently starting a second watchdog.

## Priority Stop and bounded work

Emergency Stop persists a monotonic stop epoch before waiting for the mutation lock. Newer stop intent wins over stale transaction snapshots. In-flight generation/rotation/restore/optimization checks cancellation between address/DAD/source-probe/runtime stages and rolls back without restarting the old runtime after Stop. Cleanup can remain queued in the owned ledger; Stop verifies process shutdown, not instant removal of every alias.

A currently running kernel command/DAD/probe completes its bounded timeout before a checkpoint can cancel it. This is cooperative cancellation, not instantaneous interruption. `MAX_OPERATION_SECONDS` defaults to 240 (10..600); a batch exceeding it rolls back rather than running all 1024 sequential probes indefinitely. Increase counts gradually and split slow batches. Inspect pending/uncertain operations instead of blindly retrying timed-out mutations.
