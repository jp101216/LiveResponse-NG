# Demo

## `linux-detection-demo.sh`

A safe, self-cleaning demonstration of what `lrng` flags on a compromised Linux
host — useful for a screen recording or a quick "does it actually catch things"
check.

It stages **benign stand-ins** for six common Linux attacker TTPs, runs a triage,
prints what fired, and leaves the report as `lrng-demo-report.html`: the
[report viewer](../README.md#report-viewer) with the report inside, to open in
any browser. Nothing in it is malicious:

- every "payload" is `/bin/sleep`;
- the only addresses used are the RFC 5737 documentation range
  (`203.0.113.0/24`), which routes nowhere;
- the reverse-shell and fetch-and-run lines are inert text in a cron file:
  they're scheduled for 31 February, a date cron never reaches, so they can't
  fire even on a host where `crond` is running (or if the demo is killed before
  it cleans up);
- everything staged is removed on exit (even on Ctrl-C); only the report
  stays, owned by you even under `sudo`.

This is how a detection engineer validates rules: the point is to watch the tool
catch the artifacts, not to run an attack.

### What it stages → what should fire

| Staged (benign) | Rule | ATT&CK |
|---|---|---|
| A `sleep` copy run from `/tmp/.lrng-demo/` | `process.unusual_exec_path` | T1036 |
| A process whose `comm` is renamed to `kworker/0:9` | `process.kthread_masquerade` | T1036.004 |
| `/etc/cron.d` entry pointing at the `/tmp` payload | `persistence.unusual_path` | T1543 |
| A `curl … \| sh` cron line | `exec.download_pipe_shell` | T1059.004 |
| A `bash -i >& /dev/tcp/…` cron line | `exec.reverse_shell` | T1059.004 |
| A systemd user unit whose `ExecStart` is the `/tmp` payload | `persistence.unusual_path` | T1543 |

### Run it

```sh
make build            # produces ./lrng
sudo ./demo/linux-detection-demo.sh
# or, if lrng is elsewhere, or to put the report somewhere else:
LRNG=/path/to/lrng REPORT=/tmp/demo.html ./demo/linux-detection-demo.sh
```

Run as root to see processes, sockets and persistence across all users (the way a
responder would); unprivileged, it still catches everything the demo stages under
your own account.
