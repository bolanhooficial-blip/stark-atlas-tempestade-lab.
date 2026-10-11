#!/bin/sh
# Runs only INSIDE Linux user/mount/net/PID namespace. No non-isolated fallback.
set -eu
ROOT="$1"
[ -d "$ROOT/app" ] || exit 91
[ -f "$ROOT/app/worker.py" ] || exit 92
mount --make-rprivate /
for d in usr lib lib64 opt/pyvenv; do
  mkdir -p "$ROOT/$d"
  mount --bind "/$d" "$ROOT/$d"
  mount -o remount,bind,ro "$ROOT/$d"
done
# Libraries need only dynamic loading. No /etc, /home, /root, /mnt, /proc, /sys or network.
for d in null urandom zero; do
  [ -f "$ROOT/dev/$d" ] || exit 95
  mount --bind "/dev/$d" "$ROOT/dev/$d"
  mount -o remount,bind,ro "$ROOT/dev/$d"
done
mount -t tmpfs -o nosuid,nodev,noexec,size=32m tmpfs "$ROOT/tmp"
# Force control of the effective filesystem. Privileges are removed on exec.
exec /usr/sbin/chroot "$ROOT" /usr/bin/setpriv --bounding-set=-all --no-new-privs /opt/pyvenv/bin/python -I /app/worker.py
