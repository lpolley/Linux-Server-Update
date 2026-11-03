import builtins, json, os, sys, shutil
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import linux_patch as lp

base = Path(__file__).parent / "test_state"
shutil.rmtree(base, ignore_errors=True)
lp.STATE_DIR = lp.LOG_DIR = base
lp.SCAN_REPORT = base / "scan_report.json"
lp.APPROVAL_FILE = base / "approval.json"
lp.LOCK_FILE = base / "lock"
lp.AUDIT_LOG = base / "audit.jsonl"
os.umask(0o077)
lp.prepare_directories()
lp.setup_logging()

APT_SIM = """Reading package lists...
Inst openssl [3.0.11-1~deb12u1] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [arm64])
Inst libssl3 [3.0.11-1~deb12u1] (3.0.15-1~deb12u1 Debian:12.8/stable, Debian-Security:12/stable-security [arm64]) []
Inst curl [7.88.1-10] (7.88.1-10+deb12u8 Debian:12.8/stable [arm64])
Inst libnew1 (1.0-1 Debian:12.8/stable [arm64])
Remv oldpkg [1.0]
Conf openssl (3.0.15-1~deb12u1 Debian-Security:12/stable-security [arm64])
"""
r = lp.parse_apt_simulation(APT_SIM)
assert [u["name"] for u in r["upgrades"]] == ["openssl", "libssl3", "curl"], r
assert [u["security"] for u in r["upgrades"]] == [True, True, False]
assert r["installs"] == ["libnew1"] and r["removals"] == ["oldpkg"]
print("apt parser OK")

DNF4 = """Dependencies resolved.
================================================================
 Package                 Arch    Version          Repository  Size
================================================================
Upgrading:
 openssl                 x86_64  1:3.0.7-27.el9   baseos     1.2 M
 a-really-long-package-name-that-wraps
                         noarch  2.0-1.el9        appstream   10 k
Installing dependencies:
 libfoo                  x86_64  1.0-1.el9        baseos      50 k
Removing dependent packages:
 legacy                  x86_64  0.9-1.el9        @baseos     20 k

Transaction Summary
================================================================
Upgrade  2 Packages
"""
r = lp.parse_dnf_transaction(DNF4)
assert r == {"upgrades": ["openssl", "a-really-long-package-name-that-wraps"],
             "installs": ["libfoo"], "removals": ["legacy"]}, r
DNF5 = """Package        Arch    Version          Repository   Size
Upgrading:
 openssl       x86_64  1:3.2.2-1.fc41   updates   2.1 MiB
   replacing openssl x86_64 1:3.2.1-1.fc41 updates 2.1 MiB
Transaction Summary:
 Upgrading:         1 package
"""
r = lp.parse_dnf_transaction(DNF5)
assert r == {"upgrades": ["openssl"], "installs": [], "removals": []}, r
print("dnf parser OK")

# --- DnfBackend against dnf4 (Rocky 9) behaviour, with run_command faked ---
class Result:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr

def fake_dnf(responses):
    def run(args, timeout, allowed_codes=(0,)):
        for key, value in responses.items():
            if key in " ".join(args):
                if isinstance(value, Exception):
                    raise value
                return value
        raise AssertionError(f"unexpected command {args}")
    return run

real_run = lp.run_command
dnf = lp.DnfBackend()

# assumeno prints "Error: Operation aborted." on a good transaction
lp.run_command = fake_dnf({"--assumeno": Result(
    "Dependencies resolved.\n" + DNF4 + "Operation aborted.\n", 1,
    "Error: Operation aborted.\n")})
assert dnf.simulate([{"name": "openssl", "version": "1:3.0.7-27.el9", "arch": "x86_64"}])["upgrades"]
# a real dependency error still fails
lp.run_command = fake_dnf({"--assumeno": Result("", 1,
    "Error: Problem: conflicting requests\n")})
try:
    dnf.simulate([{"name": "openssl", "version": "1:3.0.7-27.el9", "arch": "x86_64"}])
    raise AssertionError("should have failed")
except lp.CommandError:
    pass

# security flag matches dnf4 NEVRAs that include the epoch
lp.run_command = fake_dnf({
    "repoquery": Result("openssl|1:3.0.7-28.el9_4|x86_64|baseos\ncurl|7.76.1-29.el9_4|x86_64|baseos\nvim-minimal|2:8.2.2637-21.el9|x86_64|baseos\n"),
    "rpm -qa": Result("openssl|x86_64|1:3.0.7-27.el9\ncurl|x86_64|7.76.1-26.el9\nvim-minimal|x86_64|2:8.2.2637-20.el9\n"),
    "updateinfo": Result("RLSA-2024:3501 Moderate/Sec. openssl-1:3.0.7-28.el9_4.x86_64\nRLSA-2024:3502 Important/Sec. curl-7.76.1-29.el9_4.x86_64\n"),
})
ups = {u["name"]: u for u in dnf.list_upgrades()}
assert ups["openssl"]["security"] is True and ups["curl"]["security"] is True
assert ups["vim-minimal"]["security"] is False
assert ups["openssl"]["current"] == "1:3.0.7-27.el9"

# needs-restarting: missing plugin must not mean "reboot required"
lp.kernel_reboot_reasons = lambda: []
lp.run_command = fake_dnf({"needs-restarting": Result("", 1, "No such command: needs-restarting.\n")})
assert dnf.reboot_status()["pending"] is False
lp.run_command = fake_dnf({"needs-restarting": Result(
    "Core libraries or services have been updated since boot-up:\n  * kernel\n\nReboot is required to fully utilize these updates.\n", 1)})
assert dnf.reboot_status()["pending"] is True
lp.run_command = fake_dnf({"needs-restarting": Result(
    "No core libraries or services have been updated since boot-up.\nReboot should not be necessary.\n", 0)})
assert dnf.reboot_status()["pending"] is False
lp.run_command = real_run
print("dnf backend OK")


class FakeBackend:
    name = "fake"
    sim_extra = []
    removals = []
    installed = []
    def refresh(self): pass
    def list_upgrades(self): return lp.parse_apt_simulation(APT_SIM)["upgrades"]
    def simulate(self, pkgs):
        return {"upgrades": [p["name"] for p in pkgs] + self.sim_extra,
                "installs": ["libnew1"], "removals": self.removals}
    download_fails = False
    def download(self, pkgs):
        if self.download_fails:
            raise lp.CommandError("apt-get install -y exited 100: E: Unable to fetch some archives",
                output="Err:1 http://deb.debian.org/debian bullseye/main samba 404 Not Found\nE: Unable to fetch some archives")
    def install(self, pkgs):
        self.installed = pkgs
        class R: stdout = "Setting up openssl ..."
        return R()
    def health_problems(self): return []
    def reboot_status(self): return {"pending": False, "reasons": []}

lp.get_server_information = lambda: {
    "hostname": lp.socket.gethostname(), "os": "Debian 12", "kernel": "6.6",
    "hardware": "Raspberry Pi 4 Model B", "boot_time": lp.now(),
    "uptime": timedelta(hours=5)}
lp.is_maintenance_window = lambda s, e: True
sys.stdin.isatty = lambda: True
host = lp.socket.gethostname()
me = {"user": os.environ["USER"], "uid": os.getuid(), "via_sudo": True, "login_name": None}
nosudo = dict(me, via_sudo=False)
fb = FakeBackend()

def answer(text):
    builtins.input = lambda prompt="": text

assert lp.run_scan(fb, me) == 0
assert oct(lp.SCAN_REPORT.stat().st_mode & 0o777) == "0o600"



# approval refused without sudo / wrong hostname typed
assert lp.run_approve(nosudo, [], False, 24, None, None) == 3
answer("wrong"); assert lp.run_approve(me, [], False, 24, None, None) == 3
assert lp.run_approve(me, ["nope"], False, 24, None, None) == 1

# approve only openssl -> sim says libssl3 also upgrades -> blocked as unapproved
answer(host); assert lp.run_approve(me, ["openssl"], False, 24, "CHG-1", "test") == 0
fb.sim_extra = ["libssl3"]
assert lp.run_install(fb, me, False, False) == 3
assert lp.APPROVAL_FILE.exists()
fb.sim_extra = []

# removal blocked
fb.removals = ["oldpkg"]
assert lp.run_install(fb, me, False, False) == 3
fb.removals = []

# tampering: world-writable approval rejected
os.chmod(lp.APPROVAL_FILE, 0o666)
assert lp.run_install(fb, me, False, True) == 3
os.chmod(lp.APPROVAL_FILE, 0o600)

# tampering: option injection in package name
a = json.loads(lp.APPROVAL_FILE.read_text())
import copy; good = copy.deepcopy(a)
a["packages"][0]["name"] = "-oAPT::Foo=bar"
lp.write_private_json(lp.APPROVAL_FILE, a)
assert lp.run_install(fb, me, False, True) == 3
# tampering: expiry stretched past max
a = copy.deepcopy(good); a["expires"] = (lp.now() + timedelta(days=30)).isoformat()
lp.write_private_json(lp.APPROVAL_FILE, a)
assert lp.run_install(fb, me, False, True) == 3
# expired
a = copy.deepcopy(good); a["approved_at"] = (lp.now() - timedelta(hours=30)).isoformat()
a["expires"] = (lp.now() - timedelta(hours=6)).isoformat()
lp.write_private_json(lp.APPROVAL_FILE, a)
assert lp.run_install(fb, me, False, True) == 3
# other host
a = copy.deepcopy(good); a["hostname"] = "other-box"
lp.write_private_json(lp.APPROVAL_FILE, a)
assert lp.run_install(fb, me, False, True) == 3
lp.write_private_json(lp.APPROVAL_FILE, good)

# outside window without --now blocked; dry run leaves approval
lp.is_maintenance_window = lambda s, e: False
assert lp.run_install(fb, me, False, False) == 3
assert lp.run_install(fb, me, True, True) == 0 and lp.APPROVAL_FILE.exists()

# download failure keeps the approval and installs nothing
fb.download_fails = True
assert lp.run_install(fb, me, True, False) == 1
assert lp.APPROVAL_FILE.exists() and fb.installed == []
fb.download_fails = False

# real install with override -> approval consumed, replay fails
assert lp.run_install(fb, me, True, False) == 0
assert [p["name"] for p in fb.installed] == ["openssl"]
assert not lp.APPROVAL_FILE.exists()
assert lp.run_install(fb, me, True, False) == 3

# revoke
answer(host); assert lp.run_approve(me, [], True, 4, None, None) == 0
assert lp.run_revoke(me) == 0 and not lp.APPROVAL_FILE.exists()

events = [json.loads(l)["event"] for l in lp.read_audit_lines()]
print(events)
assert lp.run_history(50) == 0

# tamper with the audit log -> chain broken
lines = lp.read_audit_lines()
lines[1] = lines[1].replace("CHG-1", "CHG-2")
lp.AUDIT_LOG.write_text("\n".join(lines) + "\n")
assert lp.run_history(3) == 1
print("\nALL TESTS PASSED")
