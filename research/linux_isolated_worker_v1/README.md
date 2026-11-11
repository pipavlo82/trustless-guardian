# Linux isolated-worker pilot v1

This is a local synthetic research pilot. It never pulls an image, contacts a live gateway, uses a real credential, or accesses a third-party target. The caller must name an image already present in the local Docker cache.

The pilot validates host-side synthetic bearer admission before container creation, a non-root container user, `no-new-privileges`, zero effective capabilities, read-only rootfs, bounded writable tmpfs, `network=none`, pids/memory/CPU/file-descriptor limits, safe refusal, container removal, and a clean retry. It uses the reserved TEST-NET address `192.0.2.1` only after Docker networking is disabled.

Rootless daemon mode is reported separately. A rootful Docker Desktop daemon with a non-root, zero-capability container is an equivalent bounded pilot for these checks, not proof of rootless-container operation or production isolation.

```text
python -B -m research.linux_isolated_worker_v1.pilot --image <already-local-image-or-id> --out build/linux-pilot/report.json
```

Absent Docker or an already-local image is `NOT_COVERED`; the tool will not pull.

