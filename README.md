# linux-patch: patching Linux servers with approval and an audit trail

I built this tool to patch Linux servers under change control. You don't run
`apt upgrade` and hope. You scan, a named person approves exact package
versions, the install runs only inside a maintenance window and only if every
safety check passes, and each step goes into a tamper-evident audit log.

It is the Linux counterpart to my Windows Server patch tool
(`WindowsServerUpdateV6.py`), and the design is the same: **scan → approve →
install, failing closed at each step**. I run it on my Raspberry Pi 4 NAS
(OpenMediaVault on Raspberry Pi OS / Debian), and it supports the two biggest
Linux families:

| Family | Distros | Backend |
|---|---|---|
| Debian | Debian, Ubuntu, Raspberry Pi OS, OpenMediaVault, Mint | `apt-get` / `dpkg` (tested on Debian-format output) |
| Red Hat | RHEL, Rocky, Alma, Fedora, CentOS Stream | `dnf` 4 and 5 / `rpm` (parser unit-tested; not yet run on a live RHEL box) |

I left Arch (`pacman`) out on purpose. Arch doesn't support partial
upgrades, and installing only the approved subset of packages is exactly what
this tool does.

It uses **only the Python standard library**, so there's nothing to `pip
install`. That matters on Debian 12+, where the system Python is "externally
managed" (PEP 668) and `pip install` system-wide is blocked.

---

## Commands

```
sudo linux-patch scan                 # refresh package lists, record what's missing
sudo linux-patch approve              # approve everything from the last scan (interactive)
sudo linux-patch approve --security-only --ticket CHG-1042 --note "October patching"
sudo linux-patch approve openssl libssl3 --hours 8
sudo linux-patch install --dry-run    # every check + simulate + download, install nothing
sudo linux-patch install              # install approved updates (only in the window)
sudo linux-patch install --now        # override the window (logged as its own audit event)
sudo linux-patch revoke               # cancel the current approval
sudo linux-patch status               # scan / approval / reboot / window at a glance
sudo linux-patch history -n 30        # audit trail + integrity check
```

Exit codes match my Windows tool so a scheduler or monitoring system can act
on them: `0` OK, `1` error, `2` usage error (argparse), `3` not authorized.

## Typical workflow on my Pi

```
$ sudo linux-patch scan
Linux Server Information
------------------------
Hostname: omv
Operating System: Debian GNU/Linux 12 (bookworm)
Hardware: Raspberry Pi 4 Model B Rev 1.4
Available Updates: 3
  openssl          3.0.11-1~deb12u1 -> 3.0.15-1~deb12u1 SECURITY
  libssl3          3.0.11-1~deb12u1 -> 3.0.15-1~deb12u1 SECURITY
  curl             7.88.1-10 -> 7.88.1-10+deb12u8
Pending Reboot: False

$ sudo linux-patch approve --ticket CHG-1042
Approving 3 update(s) on omv:
  ...
Approver: lucas (uid 1000) via sudo
Expires:  2026-10-31 22:00 MDT
Type the hostname (omv) to approve: omv
Approval 0b089e9371bb2e65 recorded for lucas (uid 1000) via sudo

$ sudo linux-patch install        # at 10 PM, or run from cron
```

---

## Security controls, and why each one exists

**Approval and identity**
- **The approver is a named human.** `approve` refuses to run unless it was
  started through `sudo`. It records `SUDO_USER`/`SUDO_UID` (and checks that
  they match a real account in `/etc/passwd`), so the audit log says "lucas",
  not "root".
- **Approval is deliberate.** It needs a real terminal (no piping `yes` into
  it), and the approver must type the hostname. That's the same idea as
  GitHub making you type a repo's name before deleting it: it stops approving
  the wrong box out of muscle memory.
- **Approvals pin exact versions.** I approve `openssl=3.0.15-1~deb12u1`, not
  "openssl". If a newer version is published between approval and install,
  the tool installs only the version I reviewed.
- **Approvals are bound to this host**, expire (24h by default, 72h hard
  maximum, enforced again at load time so a hand-edited expiry gets caught),
  and are **single-use**: once an install starts, the approval is moved to
  `approval.used-<timestamp>.json`, so it can't be replayed.
- **Stale scans can't be approved.** A scan older than 24h is rejected, so
  nobody approves from out-of-date data.

**Install safety (fail closed)**
- The install is authorized only if *all* of these pass, and every reason it's
  blocked is listed: maintenance window (22:00–02:00, crossing midnight), a
  valid approval, no pending reboot, a healthy package database (`dpkg
  --audit` / `dnf check`), and at least 500 MB free on `/var`.
- **Simulate first.** Before anything is installed, the package manager does a
  dry run. The install is blocked if it would **remove or downgrade** any
  package, or **upgrade any package I didn't approve** (for example a
  dependency like `libssl3` coming along with `openssl`). New dependency
  packages are allowed, and logged.
- **Download before spending the approval.** Every package is downloaded
  *before* the approval is used up. My first real run on the Pi failed with
  "Unable to fetch some archives", which is a mirror/network problem, and at
  that point the old order had already burned the approval. Now a download
  failure keeps the approval for a retry, and logs apt's actual `Err:` lines so
  I can see which URL failed. `--dry-run` downloads too, so it catches this
  class of failure before the real run.
- **Window override is audited.** `--now` exists for emergencies and writes its
  own `window_override` audit event.
- `--force-confold` keeps my existing config files rather than replacing them
  with the package maintainer's. On OpenMediaVault that matters, because OMV
  manages its own configs.

**Command execution**
- `subprocess` gets argument lists. There is never `shell=True`, so there's no
  shell to inject into.
- Every package name and version is checked against an **allowlist regex** that
  has to start with a letter or digit. That blocks *option injection*: an
  attacker-supplied "package" like `-oAPT::...` can't turn into an apt-get
  option.
- Commands run with a **minimal environment**: fixed `PATH` (so nobody can plant
  a fake `apt-get` earlier in the path), `LC_ALL=C` (stable English output to
  parse), `DEBIAN_FRONTEND=noninteractive`, stdin closed, and a timeout on every
  call.

**Files and logs**
- State lives in `/var/lib/linux-patch`, logs in `/var/log/linux-patch`. Both
  directories are `0700`, and the process umask is `077`, so every file it
  creates is private to root.
- Before trusting `approval.json` or `scan_report.json`, the tool checks that
  the file isn't a symlink, is owned by root, and isn't group- or
  world-writable.
- JSON is written atomically (write a temp file, fsync, rename), so a crash or
  power cut can't leave a half-written approval. Power cuts are a real
  possibility on a Pi.
- A lock file (`flock`) stops two runs from patching at the same time.
- **Tamper-evident audit log** (`audit.jsonl`): one JSON event per line, and
  each line stores the SHA-256 of the line before it, like a mini blockchain.
  `history` re-checks the chain and reports the first line where it breaks.
- Free-text `--note` and `--ticket` values are validated (printable, length-
  capped) so nobody can inject fake lines into the logs with embedded newlines.

## Known limitations (and what I'd do in production)

- **Root can forge anything.** Anyone with root can rewrite the approval or the
  whole audit chain. The hash chain *detects* casual edits; it doesn't prevent
  a determined admin. In production I'd ship the audit log off the box (syslog
  / SIEM) and, if possible, make it append-only (`chattr +a`).
- **One person can approve and install.** On a single home server, separation
  of duties isn't possible. In a company, approvals would come from a change
  ticket system, signed by a different person than the one installing.
- **Reboots are manual.** The tool tells me when a reboot is needed
  (`/run/reboot-required`, a new kernel since boot, or `dnf needs-restarting`),
  but on a NAS I want to choose when to reboot.
- **OMV release upgrades** that need packages removed are blocked by design. I
  do those through the OMV web UI or `omv-upgrade`.

## Install on the Pi

```
scp linux_patch.py lucas@omv.local:/tmp/
ssh lucas@omv.local
sudo install -o root -g root -m 0755 /tmp/linux_patch.py /usr/local/sbin/linux-patch
sudo linux-patch scan
sudo linux-patch install --dry-run
```

## Install on Rocky / RHEL / Alma

The same steps, with two differences:

```
sudo install -o root -g root -m 0755 ~/linux_patch.py /usr/local/sbin/linux-patch
sudo /usr/local/sbin/linux-patch scan
```

- **Call it by its full path.** On RHEL-family systems, sudo's `secure_path`
  doesn't include `/usr/local/sbin`, so `sudo linux-patch` gives "command not
  found". That's a deliberate security control (the same idea as this tool's
  own `SAFE_PATH`), so I work with it instead of loosening it.
- **Use `install`, not `mv`.** SELinux labels files by location. `install`
  creates a new file that gets the right label for `/usr/local/sbin`; `mv`
  would keep the home-directory label. If it ever gets denied, run
  `sudo restorecon -v /usr/local/sbin/linux-patch`.

Optional nightly automation (root crontab, `sudo crontab -e`). Scan in the
morning, install during the window if I approved something that day:

```
0 7  * * *  /usr/local/sbin/linux-patch scan    >/dev/null 2>&1
30 22 * * * /usr/local/sbin/linux-patch install >/dev/null 2>&1
```

Cron runs as root without sudo, so the audit log clearly separates **who
approved** (lucas, via sudo) from **who executed** (root, the scheduler).

## Testing

`test_linux_patch.py` uses a fake package manager to test the parsers (apt,
dnf4, dnf5 output) and the full scan → approve → install flow, including these
negative tests: approving without sudo, typing the wrong hostname, an
unapproved dependency upgrade, a removal, a world-writable approval file,
option injection in a package name, expiry stretched past 72h, an expired
approval, another host's approval, running outside the window, replaying an
approval, and editing the audit log.
