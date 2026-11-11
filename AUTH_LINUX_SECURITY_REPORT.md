# Linux Isolated Worker v2 Security Report

## Boundary

The pilot is a disposable local research boundary. It does not contact Vértice, client infrastructure, third-party services, or production credentials. A signed execution grant is verified on the host before `docker run`; no grant or request is accepted from an unauthenticated receipt or anomaly score.

Sequence:

`AUTHENTICATE -> AUTHORIZE -> CONFINED EXECUTION -> EVIDENCE -> INDEPENDENT RECOMPUTE`

## Locally exercised controls

The cached `curlimages/curl:8.5.0` image was run with `--pull never`, `--network none`, read-only root, all capabilities dropped, `no-new-privileges`, UID/GID 65534, seccomp, PID 16, memory 64 MiB, CPU 0.5, file-descriptor 64, a read-only input mount, and an 8 MiB `noexec,nosuid,nodev` scratch tmpfs.

Real effects, not flag inspection alone, establish:

- root filesystem writes are denied;
- scratch is writable and reaches `ENOSPC` at its bound;
- outbound TEST-NET access is denied and only loopback is visible;
- the disposable host secret is neither mounted nor present in output and its SHA-256 is unchanged;
- the worker runs non-root with zero effective capabilities, active seccomp, and `NoNewPrivs`;
- cgroup CPU, memory, and PID limits and the file-descriptor limit are observed inside the worker;
- request mutation and grant mutation are refused before a container starts;
- an authenticated exit 42 is observed, followed by a clean independently authenticated recovery execution.

## Classification

- Local containment campaign: `VERIFIED_LOCAL_PILOT`.
- WSL unprivileged user namespace creation: `VERIFIED`.
- Rootless Docker daemon: `NOT_COVERED` because the local daemon reports built-in seccomp but not rootless mode.
- Hosted image execution: `NOT_COVERED` when no repository-pinned image is already present; no implicit pull is allowed.
- Production authenticated invocation and production rootless isolation: `NOT_COVERED`.

This report does not elevate the branch beyond `HOLD`.
