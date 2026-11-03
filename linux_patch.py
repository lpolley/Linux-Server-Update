#!/usr/bin/env python3
# Linux server patching with administrator approval and an audit trail
import argparse
import fcntl
import hashlib
import json
import logging
import os
import platform
import pwd
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
from datetime import datetime, time, timedelta
from pathlib import Path

if sys.platform.startswith("linux"):
    STATE_DIR = Path("/var/lib/linux-patch")
    LOG_DIR = Path("/var/log/linux-patch")
else:
    STATE_DIR = Path.home() / "LinuxPatch"   # lets you test on your Mac
    LOG_DIR = STATE_DIR

SCAN_REPORT = STATE_DIR / "scan_report.json"
APPROVAL_FILE = STATE_DIR / "approval.json"
LOCK_FILE = STATE_DIR / "linux-patch.lock"
AUDIT_LOG = LOG_DIR / "audit.jsonl"

# Only these directories are searched for apt-get, dnf, rpm, etc.
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Allowlists for anything that ends up on a package manager command line.
# Both must start with a letter or digit, so nothing can pose as an option (-x).
PACKAGE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+:@-]*")
VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+~:_-]*")
TICKET_PATTERN = re.compile(r"[A-Za-z0-9._#/-]{1,64}")

MAINTENANCE_START = time(22, 0)  # 10:00 PM
MAINTENANCE_END = time(2, 0)  # 2:00 AM

DEFAULT_APPROVAL_HOURS = 24
MAX_APPROVAL_HOURS = 72
MAX_SCAN_AGE_HOURS = 24
MIN_FREE_MB = 500

REFRESH_TIMEOUT = 600  # seconds
INSTALL_TIMEOUT = 3600

GENESIS_HASH = "0" * 64

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NOT_AUTHORIZED = 3  # 2 is reserved for usage errors from argparse

KNOWN_ARCHES = {
    "x86_64", "noarch", "aarch64", "i686", "ppc64le", "s390x", "armv7hl",
}

logger = logging.getLogger("linux_patch")


class ApprovalError(Exception):
    pass


class CommandError(Exception):
    def __init__(self, message, output=""):
        super().__init__(message)
        self.output = output


class PatchError(Exception):
    pass


def setup_logging():
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(LOG_DIR / "linux-patch.log")
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    ))

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("%(message)s"))

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


def prepare_directories():
    for directory in (STATE_DIR, LOG_DIR):
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)


def now():
    return datetime.now().astimezone()


# ---------------------------------------------------------------------------
# Who is running this
# ---------------------------------------------------------------------------

def get_operator():
    sudo_user = os.environ.get("SUDO_USER")
    sudo_uid = os.environ.get("SUDO_UID")

    # sudo run from a root shell reports SUDO_USER=root, which names nobody
    if sudo_user and sudo_uid and sudo_uid != "0":
        try:
            account = pwd.getpwnam(sudo_user)
        except KeyError:
            raise PatchError(f"SUDO_USER {sudo_user!r} is not a real account")
        if str(account.pw_uid) != sudo_uid:
            raise PatchError("SUDO_USER and SUDO_UID do not match")
        user, uid, via_sudo = sudo_user, account.pw_uid, True
    else:
        uid = os.getuid()
        user = pwd.getpwuid(uid).pw_name
        via_sudo = False

    try:
        login_name = os.getlogin()
    except OSError:
        login_name = None   # no controlling terminal, e.g. cron

    return {
        "user": user,
        "uid": uid,
        "via_sudo": via_sudo,
        "login_name": login_name,
    }


def describe_operator(operator):
    text = f"{operator['user']} (uid {operator['uid']})"
    if operator["via_sudo"]:
        text += " via sudo"
    return text


# ---------------------------------------------------------------------------
# Files, locking and the audit trail
# ---------------------------------------------------------------------------

def acquire_lock():
    handle = open(LOCK_FILE, "w")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise PatchError("Another linux_patch run is in progress")
    return handle


def check_private_file(path):
    info = os.lstat(path)

    if stat.S_ISLNK(info.st_mode):
        raise PatchError(f"{path} is a symlink")

    if info.st_uid != os.geteuid():
        raise PatchError(f"{path} is not owned by the account running this tool")

    if info.st_mode & 0o022:
        raise PatchError(f"{path} is writable by group or others")


def write_private_json(path, data):
    temp_path = path.with_name(path.name + ".tmp")
    temp_path.unlink(missing_ok=True)

    fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(data, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())

    os.replace(temp_path, path)


def read_audit_lines():
    try:
        return AUDIT_LOG.read_text().splitlines()
    except FileNotFoundError:
        return []


def hash_line(line):
    return hashlib.sha256(line.encode()).hexdigest()


def append_audit(event, operator, **details):
    lines = read_audit_lines()
    previous_hash = hash_line(lines[-1]) if lines else GENESIS_HASH

    entry = {
        "time": now().isoformat(),
        "event": event,
        "host": socket.gethostname(),
        "operator": operator,
        **details,
        "prev_hash": previous_hash,
    }
    line = json.dumps(entry, sort_keys=True)

    fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a") as handle:
        handle.write(line + "\n")


def find_broken_audit_line(lines):
    expected = GENESIS_HASH
    for number, line in enumerate(lines, start=1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return number
        if entry.get("prev_hash") != expected:
            return number
        expected = hash_line(line)
    return None


# ---------------------------------------------------------------------------
# Running commands safely
# ---------------------------------------------------------------------------

def run_command(args, timeout, allowed_codes=(0,)):
    env = {
        "PATH": SAFE_PATH,
        "LC_ALL": "C",
        "DEBIAN_FRONTEND": "noninteractive",
        "HOME": "/root",
    }

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        raise CommandError(f"{args[0]} is not installed")
    except subprocess.TimeoutExpired:
        raise CommandError(f"{args[0]} timed out after {timeout}s")

    if result.returncode not in allowed_codes:
        output = (result.stderr or result.stdout).strip().splitlines()
        detail = output[-1] if output else "no output"
        raise CommandError(
            f"{' '.join(args[:3])} exited {result.returncode}: {detail}",
            output=result.stdout + result.stderr,
        )

    return result


# ---------------------------------------------------------------------------
# Server information
# ---------------------------------------------------------------------------

def get_uptime_seconds():
    return float(Path("/proc/uptime").read_text().split()[0])


def get_boot_time():
    return now() - timedelta(seconds=get_uptime_seconds())


def get_os_name():
    # Parsed by hand: platform.freedesktop_os_release() needs Python 3.10+
    try:
        lines = Path("/etc/os-release").read_text().splitlines()
    except OSError:
        return platform.platform()

    for line in lines:
        key, _, value = line.partition("=")
        if key == "PRETTY_NAME":
            return value.strip().strip('"')

    return platform.platform()


def get_hardware_model():
    try:
        model = Path("/proc/device-tree/model").read_text(errors="ignore")
        return model.strip("\x00").strip()
    except OSError:
        return platform.machine()


def get_server_information():
    return {
        "hostname": socket.gethostname(),
        "os": get_os_name(),
        "kernel": platform.release(),
        "hardware": get_hardware_model(),
        "boot_time": get_boot_time(),
        "uptime": timedelta(seconds=get_uptime_seconds()),
    }


def format_uptime(uptime):
    total_seconds = int(uptime.total_seconds())

    days = total_seconds // 86400
    remaining_seconds = total_seconds % 86400

    hours = remaining_seconds // 3600
    remaining_seconds = remaining_seconds % 3600

    minutes = remaining_seconds // 60

    return f"{days}d {hours}h {minutes}m"


def free_disk_mb(path="/var"):
    return shutil.disk_usage(path).free // (1024 * 1024)


def kernel_reboot_reasons():
    reasons = []
    running = platform.release()
    modules_dir = Path("/lib/modules")

    if not modules_dir.is_dir():
        return reasons

    if not (modules_dir / running).is_dir():
        reasons.append(f"Running kernel {running} is no longer installed")

    boot_timestamp = get_boot_time().timestamp()
    for entry in sorted(modules_dir.iterdir()):
        if entry.name == running or not (entry / "modules.dep").exists():
            continue
        if entry.stat().st_mtime > boot_timestamp:
            reasons.append(f"Kernel {entry.name} installed since last boot")

    return reasons


# ---------------------------------------------------------------------------
# Package manager backends
# ---------------------------------------------------------------------------

APT_INST = re.compile(
    r"^Inst (?P<name>\S+) (?:\[(?P<current>[^\]]+)\] )?"
    r"\((?P<candidate>\S+) (?P<origin>.*?) \[(?P<arch>[^\]]+)\]\)"
)
APT_REMV = re.compile(r"^Remv (?P<name>\S+)")


def parse_apt_simulation(text):
    upgrades = []
    installs = []
    removals = []

    for line in text.splitlines():
        match = APT_INST.match(line)
        if match:
            if match["current"]:
                upgrades.append({
                    "name": match["name"],
                    "current": match["current"],
                    "candidate": match["candidate"],
                    "arch": match["arch"],
                    "source": match["origin"],
                    "security": "security" in match["origin"].lower(),
                })
            else:
                installs.append(match["name"])
            continue

        match = APT_REMV.match(line)
        if match:
            removals.append(match["name"])

    return {"upgrades": upgrades, "installs": installs, "removals": removals}


class AptBackend:
    name = "apt"

    def refresh(self):
        logger.info("Refreshing package lists (apt-get update)")
        run_command(["apt-get", "update", "-q"], timeout=REFRESH_TIMEOUT)

    def list_upgrades(self):
        result = run_command(
            ["apt-get", "-s", "-q", "dist-upgrade"], timeout=REFRESH_TIMEOUT
        )
        return parse_apt_simulation(result.stdout)["upgrades"]

    def package_specs(self, packages):
        return [f"{package['name']}={package['version']}" for package in packages]

    def simulate(self, packages):
        result = run_command(
            ["apt-get", "-s", "-q", "install", "--only-upgrade",
             *self.package_specs(packages)],
            timeout=REFRESH_TIMEOUT,
        )
        simulation = parse_apt_simulation(result.stdout)
        simulation["upgrades"] = [u["name"] for u in simulation["upgrades"]]
        return simulation

    def download(self, packages):
        run_command(
            ["apt-get", "install", "-y", "-q", "--download-only",
             "--only-upgrade", *self.package_specs(packages)],
            timeout=INSTALL_TIMEOUT,
        )

    def install(self, packages):
        return run_command(
            ["apt-get", "install", "-y", "-q", "--only-upgrade",
             "-o", "Dpkg::Options::=--force-confdef",
             "-o", "Dpkg::Options::=--force-confold",
             *self.package_specs(packages)],
            timeout=INSTALL_TIMEOUT,
        )

    def health_problems(self):
        result = run_command(["dpkg", "--audit"], timeout=120)
        if result.stdout.strip():
            return ["dpkg reports half-installed packages (run: dpkg --audit)"]
        return []

    def reboot_status(self):
        reasons = []
        flag = Path("/run/reboot-required")
        if flag.exists():
            packages_file = Path("/run/reboot-required.pkgs")
            packages = []
            if packages_file.exists():
                packages = packages_file.read_text().split()
            detail = f" ({', '.join(packages)})" if packages else ""
            reasons.append(f"/run/reboot-required is present{detail}")

        reasons.extend(kernel_reboot_reasons())
        return {"pending": len(reasons) > 0, "reasons": reasons}


def parse_dnf_transaction(text):
    upgrades = []
    installs = []
    removals = []
    section = None

    for line in text.splitlines():
        if not line.strip():
            continue

        if not line.startswith(" "):
            header = line.strip()
            if not header.endswith(":"):
                section = None
            elif header.startswith(("Upgrading", "Updating")):
                section = upgrades
            elif header.startswith("Installing"):
                section = installs
            elif header.startswith(("Removing", "Erasing", "Downgrading")):
                section = removals
            else:
                section = None
            continue

        if section is None:
            continue

        first = line.split()[0]
        if first in ("replacing", "Package") or first in KNOWN_ARCHES:
            continue
        section.append(first)

    return {"upgrades": upgrades, "installs": installs, "removals": removals}


class DnfBackend:
    name = "dnf"

    def refresh(self):
        logger.info("Refreshing package metadata (dnf makecache)")
        run_command(["dnf", "-q", "makecache"], timeout=REFRESH_TIMEOUT)

    def installed_versions(self):
        result = run_command(
            ["rpm", "-qa", "--qf", "%{NAME}|%{ARCH}|%{EVR}\n"], timeout=120
        )
        installed = {}
        for line in result.stdout.splitlines():
            parts = line.split("|")
            if len(parts) == 3:
                installed[(parts[0], parts[1])] = parts[2]
        return installed

    def security_nevras(self):
        try:
            result = run_command(
                ["dnf", "-q", "updateinfo", "list", "--security"],
                timeout=REFRESH_TIMEOUT,
            )
        except CommandError:
            return None
        return set(result.stdout.split())

    def list_upgrades(self):
        result = run_command(
            ["dnf", "-q", "repoquery", "--upgrades", "--latest-limit", "1",
             "--qf", "%{name}|%{evr}|%{arch}|%{reponame}\n"],
            timeout=REFRESH_TIMEOUT,
        )
        installed = self.installed_versions()
        security = self.security_nevras()

        upgrades = []
        for line in result.stdout.splitlines():
            parts = [part.strip() for part in line.replace("\\n", "").split("|")]
            if len(parts) != 4:
                continue
            name, evr, arch, repo = parts
            version_release = evr.split(":", 1)[-1]
            upgrades.append({
                "name": name,
                "current": installed.get((name, arch), "unknown"),
                "candidate": evr,
                "arch": arch,
                "source": repo,
                # dnf4 lists epoch-bearing packages with the epoch, dnf5 without
                "security": (
                    None if security is None
                    else f"{name}-{version_release}.{arch}" in security
                    or f"{name}-{evr}.{arch}" in security
                ),
            })
        return upgrades

    def package_specs(self, packages):
        return [
            f"{package['name']}-{package['version']}.{package['arch']}"
            for package in packages
        ]

    def simulate(self, packages):
        result = run_command(
            ["dnf", "upgrade", "--assumeno", *self.package_specs(packages)],
            timeout=REFRESH_TIMEOUT,
            allowed_codes=(0, 1),
        )
        # --assumeno makes dnf4 print "Error: Operation aborted." on success
        output = result.stdout + result.stderr
        for line in output.splitlines():
            if line.startswith("Error:") and "Operation aborted" not in line:
                raise CommandError(
                    f"dnf could not resolve the transaction: {line}",
                    output=output,
                )
        return parse_dnf_transaction(result.stdout)

    def download(self, packages):
        run_command(
            ["dnf", "-y", "upgrade", "--downloadonly",
             *self.package_specs(packages)],
            timeout=INSTALL_TIMEOUT,
        )

    def install(self, packages):
        return run_command(
            ["dnf", "-y", "upgrade", *self.package_specs(packages)],
            timeout=INSTALL_TIMEOUT,
        )

    def health_problems(self):
        try:
            run_command(["dnf", "-q", "check"], timeout=300)
        except CommandError as error:
            return [f"dnf check failed: {error}"]
        return []

    def reboot_status(self):
        reasons = []
        try:
            result = run_command(
                ["dnf", "needs-restarting", "-r"],
                timeout=120,
                allowed_codes=(0, 1),
            )
        except CommandError:
            result = None

        # Exit code 1 also means "No such command" when the plugin is
        # missing, so only trust it together with the plugin's own message
        if result is not None and result.returncode == 0:
            pass
        elif result is not None and "Reboot is required" in result.stdout:
            reasons.append("dnf needs-restarting reports a reboot is required")
        else:
            reasons.extend(kernel_reboot_reasons())
        return {"pending": len(reasons) > 0, "reasons": reasons}


def detect_backend():
    if shutil.which("apt-get", path=SAFE_PATH):
        return AptBackend()
    if shutil.which("dnf", path=SAFE_PATH):
        return DnfBackend()
    raise PatchError(
        "No supported package manager found (supported: apt, dnf)"
    )


# ---------------------------------------------------------------------------
# Validation of saved state
# ---------------------------------------------------------------------------

def validate_package_entry(package):
    if not isinstance(package, dict):
        raise ApprovalError("Each package must be a JSON object")

    name = package.get("name")
    version = package.get("version")
    arch = package.get("arch")

    if not isinstance(name, str) or not PACKAGE_PATTERN.fullmatch(name):
        raise ApprovalError(f"Invalid package name: {name!r}")
    if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
        raise ApprovalError(f"Invalid version for {name}: {version!r}")
    if not isinstance(arch, str) or not PACKAGE_PATTERN.fullmatch(arch):
        raise ApprovalError(f"Invalid architecture for {name}: {arch!r}")


def parse_timestamp(value, field):
    try:
        timestamp = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        raise ApprovalError(f"'{field}' is not a valid timestamp")
    if timestamp.tzinfo is None:
        raise ApprovalError(f"'{field}' must include a UTC offset")
    return timestamp


def load_scan_report(hostname):
    try:
        check_private_file(SCAN_REPORT)
        report = json.loads(SCAN_REPORT.read_text())
    except FileNotFoundError:
        raise ApprovalError("No scan report found, run: linux_patch scan")
    except PatchError as error:
        raise ApprovalError(f"Scan report rejected: {error}")
    except json.JSONDecodeError as error:
        raise ApprovalError(f"Scan report is not valid JSON: {error}")

    if not isinstance(report, dict):
        raise ApprovalError("Scan report must contain a JSON object")

    if str(report.get("hostname", "")).lower() != hostname.lower():
        raise ApprovalError("Scan report is from a different host")

    scanned_at = parse_timestamp(report.get("scanned_at"), "scanned_at")
    age = now() - scanned_at
    if age > timedelta(hours=MAX_SCAN_AGE_HOURS):
        raise ApprovalError(
            f"Scan report is {format_uptime(age)} old, run scan again"
        )

    updates = report.get("updates")
    if not isinstance(updates, list):
        raise ApprovalError("Scan report has no update list")

    for update in updates:
        if not isinstance(update, dict):
            raise ApprovalError("Scan report contains an invalid update entry")
        validate_package_entry({
            "name": update.get("name"),
            "version": update.get("candidate"),
            "arch": update.get("arch"),
        })

    return report


def load_approval(hostname):
    try:
        check_private_file(APPROVAL_FILE)
        approval = json.loads(APPROVAL_FILE.read_text())
    except FileNotFoundError:
        raise ApprovalError(f"No approval file at {APPROVAL_FILE}")
    except PatchError as error:
        raise ApprovalError(str(error))
    except json.JSONDecodeError as error:
        raise ApprovalError(f"Approval file is not valid JSON: {error}")

    if not isinstance(approval, dict):
        raise ApprovalError("Approval file must contain a JSON object")

    approved_by = approval.get("approved_by")
    if (
        not isinstance(approved_by, dict)
        or not isinstance(approved_by.get("user"), str)
        or not isinstance(approved_by.get("uid"), int)
        or approved_by.get("via_sudo") is not True
    ):
        raise ApprovalError("Approval is missing a valid 'approved_by'")

    approved_host = str(approval.get("hostname", ""))
    if approved_host.lower() != hostname.lower():
        raise ApprovalError(
            f"Approval is for host {approved_host!r}, not {hostname!r}"
        )

    approved_at = parse_timestamp(approval.get("approved_at"), "approved_at")
    expires = parse_timestamp(approval.get("expires"), "expires")
    current_time = now()

    if approved_at > current_time + timedelta(minutes=5):
        raise ApprovalError("Approval is dated in the future")

    if expires - approved_at > timedelta(hours=MAX_APPROVAL_HOURS):
        raise ApprovalError(
            f"Approval lasts longer than the {MAX_APPROVAL_HOURS}h maximum"
        )

    if current_time >= expires:
        raise ApprovalError(f"Approval expired at {expires.isoformat()}")

    packages = approval.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ApprovalError("'packages' must be a non-empty list")

    for package in packages:
        validate_package_entry(package)

    approval["approved_at"] = approved_at
    approval["expires"] = expires
    return approval


def retire_approval(label):
    stamp = now().strftime("%Y%m%d-%H%M%S")
    retired = STATE_DIR / f"approval.{label}-{stamp}.json"
    os.replace(APPROVAL_FILE, retired)
    return retired


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def is_maintenance_window(start_time, end_time):
    current_time = now().time()

    if start_time <= end_time:
        return start_time <= current_time < end_time

    return (
        current_time >= start_time
        or current_time < end_time
    )


def build_install_plan(backend, approval):
    problems = []
    available = {update["name"]: update for update in backend.list_upgrades()}
    approved_names = {package["name"] for package in approval["packages"]}

    to_install = []
    for package in approval["packages"]:
        update = available.get(package["name"])
        if update is None:
            logger.info("%s is already up to date, skipping", package["name"])
            continue
        if update["candidate"] != package["version"]:
            logger.warning(
                "%s: newer version %s published since approval, "
                "installing approved version %s only",
                package["name"], update["candidate"], package["version"]
            )
        to_install.append(package)

    if not to_install:
        return {"packages": [], "new_dependencies": [], "problems": problems}

    try:
        simulation = backend.simulate(to_install)
    except CommandError as error:
        problems.append(
            f"Install simulation failed ({error}), scan and approve again"
        )
        return {"packages": to_install, "new_dependencies": [], "problems": problems}

    for removal in simulation["removals"]:
        problems.append(f"Install would remove or downgrade {removal}")

    unapproved = sorted(set(simulation["upgrades"]) - approved_names)
    if unapproved:
        problems.append(
            "Install would also upgrade unapproved packages: "
            + ", ".join(unapproved)
        )

    for name in simulation["installs"]:
        logger.info("New dependency will be installed: %s", name)

    return {
        "packages": to_install,
        "new_dependencies": simulation["installs"],
        "problems": problems,
    }


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def log_server_information(server):
    logger.info("Linux Server Information")
    logger.info("------------------------")
    logger.info("Hostname: %s", server["hostname"])
    logger.info("Operating System: %s", server["os"])
    logger.info("Kernel: %s", server["kernel"])
    logger.info("Hardware: %s", server["hardware"])
    logger.info("Last Boot: %s", server["boot_time"].strftime("%Y-%m-%d %H:%M"))
    logger.info("Uptime: %s", format_uptime(server["uptime"]))


def run_scan(backend, operator):
    logger.info("Starting scan")

    server = get_server_information()
    log_server_information(server)

    backend.refresh()
    updates = backend.list_upgrades()

    logger.info("Available Updates: %d", len(updates))
    for update in updates:
        security = {True: "SECURITY", False: "", None: "?"}[update["security"]]
        logger.info(
            "  %-30s %s -> %s %s",
            update["name"], update["current"], update["candidate"], security
        )

    reboot_status = backend.reboot_status()
    logger.info("Pending Reboot: %s", reboot_status["pending"])
    for reason in reboot_status["reasons"]:
        logger.info("Reboot Reason: %s", reason)

    scan_id = hashlib.sha256(
        json.dumps(updates, sort_keys=True).encode()
    ).hexdigest()

    report = {
        "scan_id": scan_id,
        "scanned_at": now().isoformat(),
        "hostname": server["hostname"],
        "os": server["os"],
        "kernel": server["kernel"],
        "hardware": server["hardware"],
        "last_boot": server["boot_time"].isoformat(),
        "package_manager": backend.name,
        "pending_reboot": reboot_status,
        "updates": updates,
    }
    write_private_json(SCAN_REPORT, report)
    logger.info("Scan report written to %s", SCAN_REPORT)

    append_audit(
        "scan", operator,
        scan_id=scan_id,
        update_count=len(updates),
        security_count=sum(1 for u in updates if u["security"]),
    )
    logger.info("Scan completed")
    return EXIT_OK


def run_approve(operator, package_names, security_only, hours, ticket, note):
    hostname = socket.gethostname()

    if not operator["via_sudo"]:
        logger.error("Approvals must be made by a named user through sudo")
        return EXIT_NOT_AUTHORIZED

    if not sys.stdin.isatty():
        logger.error("Approvals must be made interactively at a terminal")
        return EXIT_NOT_AUTHORIZED

    try:
        report = load_scan_report(hostname)
    except ApprovalError as error:
        logger.error("Cannot approve: %s", error)
        return EXIT_ERROR

    updates = report["updates"]
    if security_only:
        updates = [u for u in updates if u["security"]]

    if package_names:
        by_name = {u["name"]: u for u in updates}
        missing = [name for name in package_names if name not in by_name]
        if missing:
            logger.error("Not in the scan report: %s", ", ".join(missing))
            return EXIT_ERROR
        updates = [by_name[name] for name in package_names]

    if not updates:
        logger.info("Nothing to approve")
        return EXIT_OK

    expires = now() + timedelta(hours=hours)

    print()
    print(f"Approving {len(updates)} update(s) on {hostname}:")
    for update in updates:
        flag = " [SECURITY]" if update["security"] else ""
        print(f"  {update['name']:30} {update['current']} -> "
              f"{update['candidate']}{flag}")
    print(f"Approver: {describe_operator(operator)}")
    print(f"Expires:  {expires.strftime('%Y-%m-%d %H:%M %Z')}")
    if ticket:
        print(f"Ticket:   {ticket}")
    print()

    typed = input(f"Type the hostname ({hostname}) to approve: ").strip()
    if typed != hostname:
        logger.warning("Approval cancelled by %s", describe_operator(operator))
        return EXIT_NOT_AUTHORIZED

    approval = {
        "approval_id": secrets.token_hex(8),
        "hostname": hostname,
        "approved_by": operator,
        "approved_at": now().isoformat(),
        "expires": expires.isoformat(),
        "scan_id": report["scan_id"],
        "ticket": ticket,
        "note": note,
        "packages": [
            {
                "name": u["name"],
                "version": u["candidate"],
                "arch": u["arch"],
                "security": u["security"],
            }
            for u in updates
        ],
    }
    write_private_json(APPROVAL_FILE, approval)

    append_audit(
        "approval_created", operator,
        approval_id=approval["approval_id"],
        scan_id=report["scan_id"],
        expires=approval["expires"],
        ticket=ticket,
        note=note,
        packages=[f"{p['name']}={p['version']}" for p in approval["packages"]],
    )
    logger.info(
        "Approval %s recorded for %s, expires %s",
        approval["approval_id"], describe_operator(operator), approval["expires"]
    )
    return EXIT_OK


def log_command_errors(error):
    for line in error.output.splitlines():
        if line.startswith(("E:", "Err:", "W:", "Error", "Failed")):
            logger.error("  %s", line.strip())


def run_install(backend, operator, override_window, dry_run):
    logger.info("Starting install%s", " (dry run)" if dry_run else "")
    hostname = socket.gethostname()
    reasons = []

    in_window = is_maintenance_window(MAINTENANCE_START, MAINTENANCE_END)
    logger.info("Maintenance Window Active: %s", in_window)
    if not in_window:
        if override_window:
            logger.warning(
                "Maintenance window overridden by %s", describe_operator(operator)
            )
        else:
            reasons.append("Outside maintenance window (use --now to override)")

    try:
        approval = load_approval(hostname)
    except ApprovalError as error:
        reasons.append(f"Approval rejected: {error}")
        approval = None
    else:
        logger.info(
            "Approval %s by %s, expires %s",
            approval["approval_id"],
            describe_operator(approval["approved_by"]),
            approval["expires"].isoformat()
        )

    reboot_status = backend.reboot_status()
    if reboot_status["pending"]:
        reasons.append(
            "Pending reboot detected: " + "; ".join(reboot_status["reasons"])
        )

    reasons.extend(backend.health_problems())

    free_mb = free_disk_mb()
    if free_mb < MIN_FREE_MB:
        reasons.append(f"Only {free_mb} MB free on /var (need {MIN_FREE_MB})")

    plan = None
    if approval is not None:
        backend.refresh()
        plan = build_install_plan(backend, approval)
        reasons.extend(plan["problems"])

        if not plan["packages"] and not reasons:
            logger.info("All approved packages are already installed")
            return EXIT_OK

    authorized = len(reasons) == 0
    logger.info("Patching Authorized: %s", authorized)

    if not authorized:
        for reason in reasons:
            logger.warning("Authorization blocked: %s", reason)
        if not dry_run:
            append_audit("install_blocked", operator, reasons=reasons)
        return EXIT_NOT_AUTHORIZED

    specs = [f"{p['name']}={p['version']}" for p in plan["packages"]]
    logger.info("Will install: %s", ", ".join(specs))

    # Download before spending the approval, so a network or mirror
    # failure leaves the approval usable for a retry
    logger.info("Downloading packages")
    try:
        backend.download(plan["packages"])
    except CommandError as error:
        logger.error("Download failed, approval kept: %s", error)
        log_command_errors(error)
        if not dry_run:
            append_audit("download_failed", operator,
                         approval_id=approval["approval_id"], error=str(error))
        return EXIT_ERROR

    if dry_run:
        logger.info("Dry run: packages downloaded, nothing installed, "
                    "approval left in place")
        return EXIT_OK

    if override_window and not in_window:
        append_audit("window_override", operator,
                     approval_id=approval["approval_id"])

    retired = retire_approval("used")
    logger.info("Approval consumed, moved to %s", retired)

    append_audit(
        "install_started", operator,
        approval_id=approval["approval_id"],
        approved_by=approval["approved_by"],
        packages=specs,
        new_dependencies=plan["new_dependencies"],
    )

    logger.info("Installing %d package(s), this can take several minutes",
                len(specs))
    try:
        result = backend.install(plan["packages"])
    except CommandError as error:
        logger.error("Install failed: %s", error)
        log_command_errors(error)
        append_audit("install_failed", operator,
                     approval_id=approval["approval_id"], error=str(error))
        return EXIT_ERROR

    for line in result.stdout.splitlines():
        logger.info("  %s", line)

    reboot_after = backend.reboot_status()
    append_audit(
        "install_completed", operator,
        approval_id=approval["approval_id"],
        packages=specs,
        reboot_required=reboot_after["pending"],
    )
    logger.info("Install completed")

    if reboot_after["pending"]:
        for reason in reboot_after["reasons"]:
            logger.warning("Reboot required: %s", reason)
        logger.warning("Reboot when ready: sudo systemctl reboot")

    return EXIT_OK


def run_revoke(operator):
    if not APPROVAL_FILE.exists():
        logger.info("No approval to revoke")
        return EXIT_OK

    try:
        approval_id = json.loads(APPROVAL_FILE.read_text()).get("approval_id")
    except (OSError, json.JSONDecodeError, AttributeError):
        approval_id = None

    retired = retire_approval("revoked")
    append_audit("approval_revoked", operator, approval_id=approval_id)
    logger.info("Approval revoked by %s, moved to %s",
                describe_operator(operator), retired)
    return EXIT_OK


def run_status(backend):
    hostname = socket.gethostname()
    server = get_server_information()

    print(f"Host:            {hostname} ({server['hardware']})")
    print(f"OS:              {server['os']}, kernel {server['kernel']}")
    print(f"Uptime:          {format_uptime(server['uptime'])}")
    print(f"Package manager: {backend.name}")

    try:
        report = load_scan_report(hostname)
    except ApprovalError as error:
        print(f"Last scan:       unusable ({error})")
    else:
        security = sum(1 for u in report["updates"] if u["security"])
        print(f"Last scan:       {report['scanned_at']} - "
              f"{len(report['updates'])} update(s), {security} security")

    try:
        approval = load_approval(hostname)
    except ApprovalError as error:
        print(f"Approval:        none valid ({error})")
    else:
        print(f"Approval:        {approval['approval_id']} by "
              f"{describe_operator(approval['approved_by'])}, "
              f"{len(approval['packages'])} package(s), "
              f"expires {approval['expires'].strftime('%Y-%m-%d %H:%M')}")

    reboot_status = backend.reboot_status()
    print(f"Pending reboot:  {reboot_status['pending']}")
    for reason in reboot_status["reasons"]:
        print(f"                 - {reason}")

    window = is_maintenance_window(MAINTENANCE_START, MAINTENANCE_END)
    print(f"In window:       {window} "
          f"({MAINTENANCE_START:%H:%M}-{MAINTENANCE_END:%H:%M})")
    return EXIT_OK


def run_history(count):
    lines = read_audit_lines()
    if not lines:
        print("Audit log is empty")
        return EXIT_OK

    broken = find_broken_audit_line(lines)
    if broken:
        print(f"WARNING: audit chain broken at line {broken}, "
              "the log may have been edited")
    else:
        print(f"Audit chain intact ({len(lines)} entries)")
    print()

    for line in lines[-max(count, 1):]:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            print(f"  (unreadable line) {line[:60]}")
            continue
        operator = entry.get("operator", {})
        detail = entry.get("approval_id") or ""
        print(f"  {entry.get('time', '?')[:19]}  {entry.get('event', '?'):18} "
              f"{operator.get('user', '?'):12} {detail}")

    return EXIT_OK if broken is None else EXIT_ERROR


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def approval_hours(value):
    hours = int(value)
    if not 1 <= hours <= MAX_APPROVAL_HOURS:
        raise argparse.ArgumentTypeError(
            f"must be between 1 and {MAX_APPROVAL_HOURS}"
        )
    return hours


def ticket_id(value):
    if not TICKET_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "use letters, digits and ._#/- only (max 64)"
        )
    return value


def note_text(value):
    if len(value) > 200 or not value.isprintable():
        raise argparse.ArgumentTypeError(
            "must be printable text, 200 characters max"
        )
    return value


def package_name(value):
    if not PACKAGE_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError(f"invalid package name: {value!r}")
    return value


def build_parser():
    parser = argparse.ArgumentParser(
        prog="linux_patch",
        description="Linux patch assessment and approved installation",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("scan", help="refresh package lists and report updates")

    approve = commands.add_parser(
        "approve", help="approve updates from the last scan (interactive)"
    )
    approve.add_argument("packages", nargs="*", type=package_name,
                         help="only approve these packages (default: all)")
    approve.add_argument("--security-only", action="store_true",
                         help="only approve security updates")
    approve.add_argument("--hours", type=approval_hours,
                         default=DEFAULT_APPROVAL_HOURS,
                         help=f"approval lifetime (default "
                              f"{DEFAULT_APPROVAL_HOURS}, max "
                              f"{MAX_APPROVAL_HOURS})")
    approve.add_argument("--ticket", type=ticket_id,
                         help="change ticket or reference ID")
    approve.add_argument("--note", type=note_text,
                         help="short reason for the approval")

    install = commands.add_parser(
        "install", help="install approved updates in the maintenance window"
    )
    install.add_argument("--now", action="store_true",
                         help="override the maintenance window (audited)")
    install.add_argument("--dry-run", action="store_true",
                         help="run every check, simulate and download, install nothing")

    commands.add_parser("revoke", help="cancel the current approval")
    commands.add_parser("status", help="show scan, approval and reboot state")

    history = commands.add_parser("history", help="show the audit trail")
    history.add_argument("-n", type=int, default=20,
                         help="number of entries to show (default 20)")

    return parser


def main():
    args = build_parser().parse_args()

    if sys.platform.startswith("linux") and os.geteuid() != 0:
        print("linux_patch must be run as root, e.g. sudo linux_patch "
              f"{args.command}", file=sys.stderr)
        return EXIT_ERROR

    os.umask(0o077)
    prepare_directories()
    setup_logging()

    if args.command == "history":
        return run_history(args.n)

    operator = get_operator()

    if args.command == "approve":
        with acquire_lock():
            return run_approve(operator, args.packages, args.security_only,
                               args.hours, args.ticket, args.note)

    if args.command == "revoke":
        with acquire_lock():
            return run_revoke(operator)

    backend = detect_backend()

    if args.command == "status":
        return run_status(backend)

    with acquire_lock():
        if args.command == "scan":
            return run_scan(backend, operator)
        return run_install(backend, operator, args.now, args.dry_run)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (PatchError, CommandError) as error:
        logger.error("%s", error)
        sys.exit(EXIT_ERROR)
    except KeyboardInterrupt:
        logger.error("Interrupted")
        sys.exit(EXIT_ERROR)
    except Exception:
        logger.exception("Unhandled error, aborting")
        sys.exit(EXIT_ERROR)
