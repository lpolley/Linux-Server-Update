# How linux_patch.py works, walked through in my own words

This goes through the script from top to bottom: what each part does, why I
wrote it that way, and how it maps to my Windows patch tool. Each section ends
with the line I'd use in an interview.

---

## 1. Constants and paths (top of file)

```python
if sys.platform.startswith("linux"):
    STATE_DIR = Path("/var/lib/linux-patch")
    LOG_DIR = Path("/var/log/linux-patch")
else:
    STATE_DIR = Path.home() / "LinuxPatch"   # lets you test on your Mac
```

On Windows I kept everything in `C:\ProgramData\ServerPatch`. Linux has a
standard layout (the Filesystem Hierarchy Standard): **state** goes in
`/var/lib/<app>` and **logs** in `/var/log/<app>`. Following it means
logrotate, backups and other admins find things where they expect them. The
Mac fallback is the same trick as in my Windows script, so I can develop on my
laptop.

`SAFE_PATH`, `PACKAGE_PATTERN`, `VERSION_PATTERN` and `TICKET_PATTERN` are
**allowlists**. I describe exactly what's allowed instead of trying to list
everything that's dangerous. Both name patterns must start with a letter or
digit, and that one rule is what prevents option injection (section 5).

The exit codes are the same as on Windows: 0 OK, 1 error, 3 not authorized,
with 2 left for argparse.

> **Interview line:** "I follow FHS for file placement and use allowlist
> validation for anything that reaches a command line."

## 2. Logging is set up in `main()`, not at import

In the Windows script, `logger = setup_logging()` runs as soon as the file is
imported. On Linux that breaks, because `/var/log` is root-only. A normal user
running `linux-patch --help` would crash before argparse got a chance to print
help. So I create the logger at module level with no handlers, and only attach
the file handler in `main()` **after** confirming I'm root. That also lets my
test file import the module without touching the real system.

## 3. Who is running this: `get_operator()`

Requirement #3 was "log the approval with my user". The problem is that when I
run `sudo linux-patch approve`, the process runs as **root**, and "root
approved this" tells an auditor nothing.

sudo leaves a trail in environment variables: `SUDO_USER=lucas` and
`SUDO_UID=1000`. I read those and **cross-check them against `/etc/passwd`**
with `pwd.getpwnam()`. If the name and UID don't match, I stop. Through real
sudo these variables can't be forged, because sudo resets the environment and
sets them itself. Someone who is *already root* could fake them, but root
can do anything anyway, and the README says so honestly.

`os.getlogin()` is extra evidence: it reads the login name of the terminal
session. It raises `OSError` under cron (no terminal), so I catch that and
record `None`.

> **Interview line:** "Privileged actions should be attributable to a person,
> not a shared account. I record the sudo identity and validate it against the
> account database."

## 4. Files, locking and the audit trail

**`os.umask(0o077)`** in `main()` means every file this process creates is
`rw-------` (root only), and I don't have to remember to `chmod` each one.

**`check_private_file(path)`** runs before I trust `approval.json` or the scan
report. It uses `os.lstat` (which looks at the link itself and doesn't follow
it) and rejects:
- **symlinks**: the classic attack is pointing `approval.json` at some other
  file
- files **not owned by me** (root in production)
- files **writable by group/others** (`st_mode & 0o022`). If anyone else could
  have edited it, I can't trust it.

**`write_private_json()`** writes to a `.tmp` file, `fsync`s it to disk, then
`os.replace()`s it into place. A rename is *atomic*, so the file is either the
old version or the new one, never half-written. On a Pi that loses power,
that's a real failure I'm guarding against. `O_EXCL` means I always create a
fresh temp file and never reuse one somebody planted.

**`acquire_lock()`** uses `fcntl.flock` with `LOCK_NB`. If cron starts an
install while I'm also running one by hand, the second run fails immediately
instead of having two apt processes fight over the package database. The
kernel releases the lock automatically if the process dies, so a crash can't
leave a stale lock behind.

**`append_audit()`** and **`find_broken_audit_line()`** make a **hash
chain**. Every audit line is JSON and contains `prev_hash`, the SHA-256 of the
previous line (the first one uses 64 zeros, the "genesis" hash). If someone
edits line 2, line 3's `prev_hash` no longer matches, and `history` reports
"chain broken at line 3". It's the same idea that makes blockchains and git
commits tamper-evident. The file is opened with `O_APPEND`, so writes always go
on the end.

> **Interview line:** "The audit log is tamper-evident, not tamper-proof. Root
> can rebuild the whole chain, so in production I'd forward it to a SIEM where
> the server's own admin can't edit it."

## 5. Running commands: `run_command()`

This is the most security-sensitive function, because it hands strings to
programs running as root.

1. **List arguments, never `shell=True`.** `["apt-get", "install", name]`
   goes straight to `execve`, with no shell to interpret `;`, `$()` or
   backticks. Shell injection is impossible.
2. **Option injection is a separate threat.** Even without a shell, if a
   "package name" were `-oAPT::Update::Pre-Invoke::=rm -rf /`, apt-get would
   read it as an **option**. My regexes require the first character to be a
   letter or digit, so nothing can start with `-`. My test suite checks this
   exact case.
3. **Minimal environment.** I don't pass along the caller's environment. I
   build a new one:
   - `PATH=SAFE_PATH`: Python looks up `apt-get` using *this* PATH, so a
     malicious `~/bin/apt-get` can't get picked up.
   - `LC_ALL=C`: forces English, predictable output. My parsers match words
     like `Inst` and `Upgrading:`, which would break on a German system.
   - `DEBIAN_FRONTEND=noninteractive` plus `stdin=DEVNULL`: a package can never
     stop and wait for keyboard input in the middle of a 10 PM install.
4. **A timeout on everything.** A hung mirror can't block the tool forever.
5. Failures become a `CommandError` that carries the last line of output, so
   the log says *why* it failed.

## 6. Server information

Same idea as `get_server_information()` on Windows, but **without `psutil`**:
- uptime comes from `/proc/uptime` (the kernel exposes it as a file), and boot
  time is now minus uptime
- the OS name comes from `/etc/os-release` via
  `platform.freedesktop_os_release()`, the Linux equivalent of reading
  `ProductName` from the registry
- the hardware model comes from `/proc/device-tree/model`, which on my Pi says
  "Raspberry Pi 4 Model B Rev 1.4". It's useful in a fleet report.

Dropping psutil means zero third-party dependencies, which matters because
Debian 12 blocks system-wide `pip install` (PEP 668).

**`kernel_reboot_reasons()`** is my equivalent of the Windows registry reboot
flags. Linux doesn't have one universal flag, so I check:
- Is the **running** kernel's `/lib/modules/<version>` directory gone? Then it
  has been replaced, and new modules won't load until a reboot.
- Does any **other** installed kernel (it has a `modules.dep`) have a directory
  that changed **after boot**? Then a new kernel was installed since I last
  rebooted.

## 7. Package manager backends: one interface, two implementations

This is the main design decision for "any flavor of Linux". `AptBackend` and
`DnfBackend` both provide the same methods:

| Method | apt | dnf |
|---|---|---|
| `refresh()` | `apt-get update` | `dnf makecache` |
| `list_upgrades()` | parse `apt-get -s dist-upgrade` | `dnf repoquery --upgrades` + `rpm -qa` |
| `simulate(pkgs)` | `apt-get -s install --only-upgrade pkg=ver` | `dnf upgrade --assumeno` |
| `install(pkgs)` | `apt-get install -y --only-upgrade ... --force-confold` | `dnf -y upgrade name-evr.arch` |
| `health_problems()` | `dpkg --audit` | `dnf check` |
| `reboot_status()` | `/run/reboot-required` + kernel check | `dnf needs-restarting -r` |

The rest of the program never mentions apt or dnf. It calls
`backend.simulate(...)`. `detect_backend()` picks one by looking for the
binary, so adding zypper (SUSE) would mean writing one new class. This is
polymorphism / the strategy pattern.

**Parsing apt.** `apt-get -s` ("simulate") prints lines like:

```
Inst openssl [3.0.11-1~deb12u1] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [arm64])
Remv oldpkg [1.0]
```

`Inst` with a `[current]` version is an **upgrade**, `Inst` without one is a
**new install** (a dependency), and `Remv` is a **removal**. I flag it as a
security update if the origin contains "security". I parse `apt-get` and not
`apt`, because `apt` itself warns that its output isn't a stable interface for
scripts.

**Parsing dnf.** dnf prints a table under section headers (`Upgrading:`,
`Installing dependencies:`, `Removing:`). I track which section I'm in and
take the first word of each indented row. Two edge cases are handled: dnf4
wraps long package names onto two lines (I skip rows that start with an
architecture like `x86_64`), and dnf5 adds `replacing` rows. Both are covered
by unit tests with sample output.

**Why `--force-confold`:** if a package ships a new default config, dpkg
normally *asks* what to do. Non-interactive, it would fail. `confdef`+`confold`
means "use the default answer, otherwise keep my existing file". On OMV that's
essential, because OMV generates its own configs.

## 8. Validating saved state: `load_scan_report()` and `load_approval()`

These come straight from my Windows `load_approval()` and follow the same
rule: **treat the file as untrusted input, even though I wrote it.**
Defense in depth.

`load_approval()` checks, in order:
1. file safety (owner, permissions, not a symlink)
2. valid JSON, and a JSON *object*
3. `approved_by` is a real structure **with `via_sudo: true`**, so a
   hand-written approval without a named approver is rejected
4. the hostname matches, so an approval copied from another server doesn't work
5. timestamps have timezones (no ambiguous "naive" datetimes, same lesson as
   on Windows)
6. `approved_at` isn't in the future, which catches clock tricks
7. **expires − approved_at ≤ 72h**, so if someone edits the expiry to next
   year, it's rejected *even though the date is still in the future*
8. it hasn't expired
9. every package name, version and arch passes the allowlist regex

`load_scan_report()` also refuses scans older than 24 hours, so nobody can
approve based on last week's data.

## 9. `build_install_plan()`: re-check right before acting

Between approving at 9 AM and installing at 10 PM, things change. So right
before installing:
- I refresh package lists and look at what's available **now**
- anything already up to date (maybe I patched it by hand) is skipped
- if a **newer** version was published, I log a warning and still install
  only the **approved** version (`pkg=version`), because that's what was
  reviewed
- then I **simulate** the exact install and block it if the simulation shows:
  - any **removal or downgrade**
  - any upgrade of a package that **wasn't approved**. If I approve `openssl`
    but apt also wants to upgrade `libssl3`, the run is blocked and tells me
    to approve both. Nothing sneaks in.

It's the same TOCTOU (time-of-check to time-of-use) lesson from my Windows
plan: check as close to the action as possible.

## 10. The commands

**`run_scan`** is read-only toward the system (apart from refreshing package
lists). It logs server info and the list of updates, writes
`scan_report.json` with a `scan_id` (the SHA-256 of the update list, so the
approval records exactly which scan it came from), and writes an audit event.

**`run_approve`** enforces the human-approval rules: started via sudo, at a
real terminal (`isatty()`, so a script can't pipe in "yes"), and with the
hostname typed back. It can filter to `--security-only` or to named packages,
which must exist in the scan. It writes `approval.json` with a random
`approval_id` (`secrets.token_hex`), and that ID shows up in every later audit
event, so I can trace approval → install → result.

**`run_install`** is my `check_patch_authorization()` from Windows, extended.
It collects **every** reason the install is blocked (window, approval, pending
reboot, package DB health, disk space, plan problems) instead of stopping at
the first one, so I can fix them all in one go. Then:
- it **downloads every package first** (`apt-get --download-only`). I added
  this after my first real run on the Pi failed partway through the download,
  *after* the approval had already been used up. Downloading only fills apt's
  cache and doesn't change the installed system, so if it fails the approval
  is kept and the failure is logged as `download_failed`, along with apt's
  `Err:` lines that show which URL broke. The lesson: put the steps that can
  fail for boring reasons (network, mirrors) *before* the step you can't take
  back.
- `--dry-run` runs all of that (including the download) and stops: no install,
  approval kept
- otherwise it **consumes the approval *before* installing** (moves it to
  `approval.used-...json`). If the install crashes halfway, the approval still
  can't be replayed. I'd rather re-approve than risk a double run.
- it installs, logs the package manager output, re-checks reboot status, and
  writes `install_completed` (or `install_failed`)
- `--now` lets me patch outside the window in an emergency, and records a
  separate `window_override` event so the exception is visible

**`run_revoke`** moves the approval to `approval.revoked-...json` (kept as
evidence, not deleted) and logs who cancelled it.

**`run_status` / `run_history`** are read-only dashboards. They use `print()`
instead of the logger so looking at status doesn't fill the log file.
`history` re-checks the hash chain each time and exits 1 if it's broken, so
monitoring can alert on it.

## 11. `main()` and the safety net

The order matters:
1. argparse runs first, so `--help` works for anyone
2. **root check**: a clear message instead of a confusing PermissionError
3. umask, then directories, then logging
4. the operator identity is resolved once and passed to whatever needs it
5. commands that change state run inside `with acquire_lock():`

argparse **type functions** (`approval_hours`, `ticket_id`, `note_text`,
`package_name`) validate input *at the edge*, before any of my code sees it.
`note_text` requires printable characters only, which blocks **log
injection**: a note with an embedded newline could otherwise forge a fake
line in the text log.

The bottom block is the fail-closed safety net I added in Windows Lesson 3:
expected errors (`PatchError`, `CommandError`) get a clean one-line message,
Ctrl-C is handled, and anything unexpected is logged with a full traceback.
Every path ends in a meaningful exit code.

## 12. Testing

`test_linux_patch.py` swaps in a `FakeBackend` (same interface, canned data),
which works *because* of the backend design in section 7. It runs on my Mac
with no Linux machine. It tests the parsers with real-format apt/dnf4/dnf5
output and then attacks the approval flow, covering the cases listed in the
README. It's the same approach as my Windows Lesson 7 negative tests, but
automated.

---

## Windows ↔ Linux cheat sheet

| Concept | Windows tool | Linux tool |
|---|---|---|
| Update source | Windows Update COM API | apt / dnf via subprocess |
| Pending reboot | registry keys (CBS, WU, PendingFileRename) | `/run/reboot-required`, kernel check, `needs-restarting` |
| OS info | registry `ProductName` / `CurrentBuild` | `/etc/os-release` |
| Uptime | psutil | `/proc/uptime` |
| State dir | `C:\ProgramData\ServerPatch` | `/var/lib/linux-patch` (0700) |
| Approval unit | KB number | package + exact version |
| Run unattended | SYSTEM scheduled task | root cron / systemd timer |
| Privilege check | (Lesson 11: run as SYSTEM) | `geteuid() == 0` |
| Identity | (README limitation) | `SUDO_USER` validated against passwd |
