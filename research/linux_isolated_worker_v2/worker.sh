#!/bin/sh
set -eu

if [ "$(id -u)" = "0" ]; then
  echo "ROOT_USER" >&2
  exit 20
fi
if ! grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status; then
  echo "NO_NEW_PRIVS_MISSING" >&2
  exit 21
fi
if ! grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status; then
  echo "CAPABILITIES_PRESENT" >&2
  exit 22
fi
if ! grep -q '"operation":"RUN_TOOL"' /input/request.json; then
  echo "REQUEST_REFUSED" >&2
  exit 23
fi
if grep -q '"mode":"crash"' /input/request.json; then
  echo "SYNTHETIC_CRASH_AFTER_ADMISSION" >&2
  exit 42
fi
if printf 'forbidden' > /etc/guardian-v2-write 2>/dev/null; then
  echo "ROOTFS_WRITE_SURVIVED" >&2
  exit 24
fi
printf 'scratch-control\n' > /tmp/control
if dd if=/dev/zero of=/tmp/overflow bs=1048576 count=12 >/dev/null 2>&1; then
  echo "SCRATCH_LIMIT_SURVIVED" >&2
  exit 25
fi
rm -f /tmp/overflow
if curl --silent --show-error --max-time 1 http://192.0.2.1/ >/dev/null 2>&1; then
  echo "NETWORK_EGRESS_SURVIVED" >&2
  exit 26
fi
if [ -e /host-secret/secret.txt ] || [ -e /input/host-secret.txt ]; then
  echo "HOST_SECRET_VISIBLE" >&2
  exit 27
fi

interfaces=$(ls -1 /sys/class/net | sort | tr '\n' ',')
pids_limit=$(cat /sys/fs/cgroup/pids.max 2>/dev/null || cat /sys/fs/cgroup/pids/pids.max 2>/dev/null || printf 'unavailable')
memory_limit=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || printf 'unavailable')
if [ -r /sys/fs/cgroup/cpu.max ]; then
  cpu_limit=$(cat /sys/fs/cgroup/cpu.max)
elif [ -r /sys/fs/cgroup/cpu/cpu.cfs_quota_us ] && [ -r /sys/fs/cgroup/cpu/cpu.cfs_period_us ]; then
  cpu_limit="$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us) $(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us)"
else
  cpu_limit=unavailable
fi
nofile_limit=$(ulimit -n)
seccomp=$(awk '/^Seccomp:/ {print $2}' /proc/self/status)
printf '{"cap_eff":"0000000000000000","cpu_max":"%s","filesystem_root":"WRITE_DENIED_OBSERVED","host_secret":"ABSENT_OBSERVED","interfaces":"%s","memory_max":"%s","network_egress":"DENIED_OBSERVED","no_new_privs":true,"nofile_limit":"%s","non_root_uid":%s,"pids_max":"%s","scratch_limit":"ENOSPC_OBSERVED","seccomp":"%s","tmpfs":"WRITABLE_OBSERVED"}\n' \
  "$cpu_limit" "$interfaces" "$memory_limit" "$nofile_limit" "$(id -u)" "$pids_limit" "$seccomp"
