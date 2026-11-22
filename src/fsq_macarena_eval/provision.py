"""One-time Golden Base VM importer and provisioner for `MacArena.utm` & `osworld.utm`.

Prepares each downloaded HuggingFace `.utm` bundle inside `~/Library/Containers/com.utmapp.UTM/Data/Documents`
so per-task clones boot ready in seconds without re-installing Conda, Node, Appium, WDA, or wheels:
1. Imports `vm_cache/<Base>.utm` into UTM Documents (if not already present), boots it once, and
   installs our Ed25519 SSH public key using `expect` (`admin`/`admin` -> key-only BatchMode SSH).
2. Pre-creates the `server` Conda environment (`~/vm_files/server/environment.yml`) + media/PyAutoGUI deps.
3. Ensures Xcode.app (`xcode-select -p` -> `/Applications/Xcode.app/Contents/Developer`), copying
   `/Applications/Xcode.app` from `MacArena.utm` into `osworld.utm` if `osworld.utm` only has CLT.
4. Installs Node 22+ & npm (if absent), installs the isolated `~/.fsq-eval-venv` containing ONLY the
   SHA256-verified frozen `appium-connect-agent==0.1.1` and `fsq-agent==0.3.6` wheels + `fsq-macarena-eval`,
   and runs `Runtime.install()` + `Runtime.ensure_managed_driver("mac2")` (`appium@3.7.0` + `mac2@4.6.1`).
5. Pre-builds `WebDriverAgentMac` (`xcodebuild build-for-testing` inside
   `~/.appium-connect-agent/driver-home/node_modules/appium-mac2-driver/WebDriverAgentMac`), seeds
   TCC Accessibility / AppleEvents permissions (`allow_permission.sh` + TCC.db if writable),
   executes a live `create_mac2_session(bundle_id="com.apple.finder")` WDA smoke check,
   syncs host `~/.fsq` provider auth into guest `~/.fsq`, runs `fsq_worker.py probe` to verify
   `passed_native_responses` (`github_copilot / gpt-6.1-sol`), and cleanly shuts down the Golden Base VM.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import plistlib
import shutil
import subprocess
import time
import sys
from pathlib import Path
from typing import Any

from .manifest import (
    FROZEN_MODEL,
    FROZEN_PROVIDER,
    INITIAL_BUNDLE_ID,
    default_frozen_wheels,
    verify_frozen_wheels,
)
from .utm_supervisor import (
    AQUA_LAUNCHAGENT_LABEL,
    AQUA_LAUNCHAGENT_REL_PATH,
    UTM_DOCUMENTS_DIR,
    ClonedVMHandle,
    DualSlotUTMSupervisor,
    UTMSupervisorError,
    resolve_guest_ip,
    run_utmctl,
)

DONOR_APPS_FROM_OSWORLD = ("Keynote.app", "Numbers.app", "Pages.app", "LibreOffice.app")


def build_aqua_launchagent_plist_bytes(
    *,
    guest_home: str = "/Users/admin",
    server_python: str = "/opt/homebrew/Caskroom/miniconda/base/envs/server/bin/python3",
) -> bytes:
    """Build `~/Library/LaunchAgents/com.fsq.macarena-server.plist` bound strictly to `Aqua` GUI sessions."""
    wrapper_cmd = (
        "export PATH=/opt/homebrew/Caskroom/miniconda/base/envs/server/bin:"
        "/opt/homebrew/Caskroom/miniconda/base/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; "
        f"mkdir -p {guest_home}/vm_files/server/screenshots; "
        f"nohup bash -lc 'chmod +x {guest_home}/vm_files/allow_permission.sh && {guest_home}/vm_files/allow_permission.sh' "
        f"> {guest_home}/allow.log 2>&1 < /dev/null & "
        f"cd {guest_home}/vm_files/server && exec {server_python} {guest_home}/vm_files/server/main.py"
    )
    doc = {
        "Label": AQUA_LAUNCHAGENT_LABEL,
        "LimitLoadToSessionType": ["Aqua"],
        "ProgramArguments": ["/bin/bash", "-lc", wrapper_cmd],
        "WorkingDirectory": f"{guest_home}/vm_files/server",
        "EnvironmentVariables": {
            "HOME": guest_home,
            "PATH": (
                "/opt/homebrew/Caskroom/miniconda/base/envs/server/bin:"
                "/opt/homebrew/Caskroom/miniconda/base/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
            ),
            "PYTHONUNBUFFERED": "1",
        },
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Interactive",
        "StandardOutPath": f"{guest_home}/macarena_server.log",
        "StandardErrorPath": f"{guest_home}/macarena_server.log",
    }
    return plistlib.dumps(doc)


def build_guest_tcc_seed_python_source() -> str:
    """Return guest Python script (executed as root) that seeds `TCC.db` for Aqua `:5000` & `osascript`."""
    return '''import os
import sqlite3
import subprocess
import time
from pathlib import Path

CANDIDATE_EXECS = [
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/osascript",
    "/usr/sbin/screencapture",
    "/usr/bin/python3",
    "/opt/homebrew/Caskroom/miniconda/base/envs/server/bin/python3",
    "/Users/admin/.fsq-eval-venv/bin/python",
]
BUNDLE_CLIENTS = [
    ("com.apple.Terminal", 0),
    ("com.apple.ScriptEditor2", 0),
]
DIRECT_SERVICES = [
    "kTCCServiceAccessibility",
    "kTCCServiceScreenCapture",
    "kTCCServicePostEvent",
    "kTCCServiceSystemPolicyAllFiles",
    "kTCCServiceAddressBook",
    "kTCCServiceReminders",
    "kTCCServiceCalendar",
]
APPLE_EVENTS_TARGETS = [
    "com.apple.systemevents",
    "com.apple.finder",
    "com.apple.Notes",
    "com.apple.Preview",
    "com.apple.iWork.Keynote",
    "com.apple.iWork.Numbers",
    "com.apple.iWork.Pages",
    "com.apple.ScriptEditor2",
    "com.apple.Automator",
    "com.apple.reminders",
    "com.apple.AddressBook",
    "com.apple.iCal",
    "com.apple.systempreferences",
    "md.obsidian",
]

resolved_paths: list[str] = []
for raw in CANDIDATE_EXECS:
    p = Path(raw)
    if p.exists():
        for cand in {str(p), str(p.resolve())}:
            if cand not in resolved_paths:
                resolved_paths.append(cand)

clients: list[tuple[str, int]] = list(BUNDLE_CLIENTS)
for rp in resolved_paths:
    clients.append((rp, 1))

system_tcc = Path("/Library/Application Support/com.apple.TCC/TCC.db")
user_tcc = Path("/Users/admin/Library/Application Support/com.apple.TCC/TCC.db")

def upsert_tcc_row(conn: sqlite3.Connection, cols: list[str], values_by_col: dict[str, object]) -> None:
    present = [c for c in cols if c in values_by_col]
    placeholders = ", ".join("?" for _ in present)
    col_sql = ", ".join(present)
    conn.execute(
        f"INSERT OR REPLACE INTO access ({col_sql}) VALUES ({placeholders})",
        [values_by_col[c] for c in present],
    )

now_ts = int(time.time())
seeded_rows = 0
errors: list[str] = []

for db_path, services in (
    (system_tcc, DIRECT_SERVICES),
    (user_tcc, ["kTCCServiceAddressBook", "kTCCServiceReminders", "kTCCServiceCalendar", "kTCCServiceAccessibility"]),
):
    if not db_path.is_file():
        continue
    try:
        conn = sqlite3.connect(str(db_path), timeout=15.0)
        cols = [row[1] for row in conn.execute("PRAGMA table_info(access)").fetchall()]
        for svc in services:
            for client_id, client_type in clients:
                base_vals = {
                    "service": svc,
                    "client": client_id,
                    "client_type": client_type,
                    "auth_value": 2,
                    "auth_reason": 4,
                    "auth_version": 1,
                    "csreq": None,
                    "policy_id": None,
                    "indirect_object_identifier_type": 0,
                    "indirect_object_identifier": "UNUSED",
                    "indirect_object_code_identity": None,
                    "flags": 0,
                    "last_modified": now_ts,
                    "pid": None,
                    "pid_version": None,
                    "boot_uuid": "UNUSED",
                    "last_reminded": 0,
                }
                upsert_tcc_row(conn, cols, base_vals)
                seeded_rows += 1
        if db_path == user_tcc:
            for target_bid in APPLE_EVENTS_TARGETS:
                for client_id, client_type in clients:
                    ae_vals = {
                        "service": "kTCCServiceAppleEvents",
                        "client": client_id,
                        "client_type": client_type,
                        "auth_value": 2,
                        "auth_reason": 4,
                        "auth_version": 1,
                        "csreq": None,
                        "policy_id": None,
                        "indirect_object_identifier_type": 0,
                        "indirect_object_identifier": target_bid,
                        "indirect_object_code_identity": None,
                        "flags": 0,
                        "last_modified": now_ts,
                        "pid": None,
                        "pid_version": None,
                        "boot_uuid": "UNUSED",
                        "last_reminded": 0,
                    }
                    upsert_tcc_row(conn, cols, ae_vals)
                    seeded_rows += 1
        conn.commit()
        conn.close()
    except Exception as exc:
        errors.append(f"{db_path}: {type(exc).__name__}: {exc}")

subprocess.run(["/usr/bin/killall", "tccd"], check=False, capture_output=True)
print({"seededRows": seeded_rows, "resolvedPaths": resolved_paths, "errors": errors})
'''


def _build_wda_tcc_ui_grant_script() -> str:
    return '''from pathlib import Path
import json, subprocess, time
from appium_connect_agent.automation import create_mac2_session
from appium_connect_agent.contracts import LocalSettings
from appium_connect_agent.runtime import OperationControl, Runtime

def flatten_non_menu(nodes, out=None):
    if out is None:
        out = []
    for n in nodes:
        t = n.get("type", "")
        if t in ("MenuBar", "MenuBarItem", "Menu", "MenuItem"):
            continue
        lbl = n.get("label", "") or n.get("title", "") or n.get("text", "")
        val = n.get("value", "")
        b = n.get("bounds")
        if t in ("Button", "Switch", "CheckBox", "StaticText", "SecureTextField", "TextField"):
            out.append((t, str(lbl)[:80], str(val)[:40], b))
        flatten_non_menu(n.get("children", []), out)
    return out

def handle_sheets(s_sys, items):
    for t, lbl, val, b in items:
        if t == "SecureTextField" and isinstance(b, list) and len(b) == 4:
            cx, cy = int(b[0] + b[2] // 2), int(b[1] + b[3] // 2)
            s_sys.device.click_at(cx, cy, control=OperationControl(timeout_seconds=10.0))
            time.sleep(0.3)
            s_sys.device.send_keys(["a", "d", "m", "i", "n", "XCUIKeyboardKeyReturn"], control=OperationControl(timeout_seconds=10.0))
            time.sleep(1.2)
            return True
    for t, lbl, val, b in items:
        if t == "Button" and lbl == "Later" and isinstance(b, list) and len(b) == 4:
            cx, cy = int(b[0] + b[2] // 2), int(b[1] + b[3] // 2)
            s_sys.device.click_at(cx, cy, control=OperationControl(timeout_seconds=10.0))
            time.sleep(0.8)
            return True
    return False

def dismiss_overlays(conn):
    return

def enable_pane_switches(s_sys, pane_url):
    subprocess.run(["open", pane_url], check=False)
    time.sleep(2.0)
    s_sys.device.activate_app("com.apple.systempreferences", control=OperationControl(timeout_seconds=10.0))
    time.sleep(1.0)
    for _ in range(10):
        doc = json.loads(s_sys.observe_tree(control=OperationControl(timeout_seconds=15.0)).to_json())
        items = flatten_non_menu(doc.get("payload", {}).get("roots", []))
        if handle_sheets(s_sys, items):
            continue
        off_switches = [b for t, _, val, b in items if t == "Switch" and val == "0" and isinstance(b, list) and len(b) == 4 and b[0] > 900]
        if not off_switches:
            break
        b = off_switches[0]
        s_sys.device.click_at(int(b[0] + b[2] // 2), int(b[1] + b[3] // 2), control=OperationControl(timeout_seconds=10.0))
        time.sleep(1.0)

node = Path("/opt/homebrew/bin/node").resolve() if Path("/opt/homebrew/bin/node").exists() else Path("/usr/local/bin/node").resolve()
npm = Path("/opt/homebrew/bin/npm").resolve() if Path("/opt/homebrew/bin/npm").exists() else Path("/usr/local/bin/npm").resolve()
rt = Runtime(LocalSettings(node_executable=node, npm_executable=npm))
with rt.start_managed(host="127.0.0.1", port=4736, base_path="", control=OperationControl(timeout_seconds=45.0)) as conn:
    dismiss_overlays(conn)
    s_sys = create_mac2_session(conn, bundle_id="com.apple.systempreferences", no_reset=True, control=OperationControl(timeout_seconds=25.0))
    try:
        enable_pane_switches(s_sys, "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
        enable_pane_switches(s_sys, "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture")
    finally:
        s_sys.quit(control=OperationControl(timeout_seconds=10.0))
    dismiss_overlays(conn)
subprocess.run(["osascript", "-e", 'tell application "System Settings" to quit'], check=False)
print("WDA_TCC_SWITCHES_ENABLED")
'''


def configure_guest_aqua_launchagent_and_tcc(
    handle: ClonedVMHandle,
    supervisor: DualSlotUTMSupervisor,
) -> dict[str, Any]:
    """Install `com.fsq.macarena-server.plist`, ensure TCC permissions, restart in `gui/<uid>`, and pass hard TCC gate."""
    plist_bytes = build_aqua_launchagent_plist_bytes()
    plist_b64 = base64.b64encode(plist_bytes).decode("ascii")
    tcc_py_b64 = base64.b64encode(build_guest_tcc_seed_python_source().encode("utf-8")).decode("ascii")

    install_cmd = (
        "set -e; "
        "echo admin | sudo -S automationmodetool enable-automationmode-without-authentication >/dev/null 2>&1 || true; "
        "mkdir -p ~/Library/LaunchAgents ~/vm_files/server/screenshots; "
        f"echo '{plist_b64}' | base64 -d > ~/{AQUA_LAUNCHAGENT_REL_PATH}; "
        f"chmod 644 ~/{AQUA_LAUNCHAGENT_REL_PATH}; "
        f"echo '{tcc_py_b64}' | base64 -d > /tmp/seed_tcc.py; "
        "TCC_OUT=$(echo admin | sudo -S python3 /tmp/seed_tcc.py 2>&1 || true); "
        "rm -f /tmp/seed_tcc.py; "
        "echo \"TCC_SEED_RESULT: $TCC_OUT\"; "
        "UID_NUM=$(id -u); "
        f"launchctl bootout \"gui/$UID_NUM\" ~/{AQUA_LAUNCHAGENT_REL_PATH} >/dev/null 2>&1 || true; "
        "pkill -f 'vm_files/server/main.py' >/dev/null 2>&1 || true; "
        "sleep 1; "
        f"launchctl bootstrap \"gui/$UID_NUM\" ~/{AQUA_LAUNCHAGENT_REL_PATH} >/dev/null 2>&1 || "
        f"launchctl kickstart -k \"gui/$UID_NUM/{AQUA_LAUNCHAGENT_LABEL}\" >/dev/null 2>&1"
    )
    out = handle.ssh_run(install_cmd, timeout=90.0).stdout.strip()
    _log(f"Aqua LaunchAgent + TCC seeded:\n{out}")
    try:
        tcc_gate = supervisor.start_guest_services(handle, verify_tcc=True)
    except UTMSupervisorError as first_err:
        _log(f"Initial TCC gate needed UI authorization ({first_err}); triggering TCC candidates & toggling via WDA...")
        import requests

        base_url = f"http://127.0.0.1:{handle.host_server_port}"
        with contextlib.suppress(Exception):
            requests.post(
                f"{base_url}/run_bash_script",
                json={
                    "script": "osascript -e 'tell application \"System Events\" to get name of first process' >/dev/null 2>&1 & /usr/sbin/screencapture -x /tmp/tcc_trig.png >/dev/null 2>&1 & sleep 1",
                    "timeout": 5,
                },
                timeout=8.0,
            )
        wda_b64 = base64.b64encode(_build_wda_tcc_ui_grant_script().encode("utf-8")).decode("ascii")
        wda_out = handle.ssh_run(
            "pkill -9 osascript screencapture >/dev/null 2>&1 || true; "
            "rm -f ~/.appium-connect-agent/records/service.json; "
            f"echo '{wda_b64}' | base64 -d > /tmp/wda_tcc_grant.py; "
            "PATH=/opt/homebrew/bin:/usr/local/bin:$PATH /Users/admin/.fsq-eval-venv/bin/python /tmp/wda_tcc_grant.py; "
            "rm -f /tmp/wda_tcc_grant.py /tmp/tcc_trig.png; "
            "UID_NUM=$(id -u); "
            f"launchctl kickstart -k \"gui/$UID_NUM/{AQUA_LAUNCHAGENT_LABEL}\" && sleep 2",
            timeout=240.0,
        ).stdout.strip()
        _log(f"WDA TCC UI grant completed: {wda_out}")
        tcc_gate = supervisor.verify_guest_aqua_tcc_readiness(handle, timeout_seconds=45.0)
    _log(f"Hard Aqua TCC readiness gate PASSED: {tcc_gate}")
    return {"seedOutput": out, "tccReadinessGate": tcc_gate}


def seed_guest_benchmark_fixtures_and_apps(
    *,
    base_vm_name: str,
    handle: ClonedVMHandle,
    supervisor: DualSlotUTMSupervisor,
) -> dict[str, Any]:
    """Bake P1-2 environment fixes into the Golden VM:

    - For `macarena`: stream missing `Keynote.app`, `Numbers.app`, `Pages.app`, `LibreOffice.app`
      from `osworld` Golden VM (`slot 1`), warm/trust Obsidian `ResearchVault`, and seed baseline Contacts.
    - For `osworld`: download Apple's `Klee` Japanese font via `CoreText` and seed `"Call him"` Reminder.
    """
    actions: dict[str, Any] = {"baseVmName": base_vm_name, "syncedApps": []}

    if base_vm_name == "macarena":
        check_py = (
            "from pathlib import Path\n"
            f"want = {list(DONOR_APPS_FROM_OSWORLD)!r}\n"
            "print('\\n'.join(a for a in want if not (Path('/Applications') / a).is_dir()))\n"
        )
        check_b64 = base64.b64encode(check_py.encode("utf-8")).decode("ascii")
        missing_apps_raw = handle.ssh_run(
            f"echo '{check_b64}' | base64 -d | python3 -",
            timeout=20.0,
        ).stdout.strip()
        missing_apps = [line.strip() for line in missing_apps_raw.splitlines() if line.strip()]
        donor_bundle = supervisor.utm_documents_dir / "osworld.utm"
        if missing_apps and donor_bundle.is_dir():
            _log(f"macarena missing {missing_apps}; booting donor 'osworld' on slot 1 to sync apps...")
            donor_handle = supervisor.acquire_disposable_vm(
                slot_id=1,
                base_vm_name="osworld",
                task_id="app-donor-osworld",
            )
            try:
                avail_py = (
                    "from pathlib import Path\n"
                    f"want = {missing_apps!r}\n"
                    "print('\\n'.join(a for a in want if (Path('/Applications') / a).is_dir()))\n"
                )
                avail_b64 = base64.b64encode(avail_py.encode("utf-8")).decode("ascii")
                avail_raw = donor_handle.ssh_run(
                    f"echo '{avail_b64}' | base64 -d | python3 -",
                    timeout=20.0,
                ).stdout.strip()
                avail_apps = [a.strip() for a in avail_raw.splitlines() if a.strip()]
                ssh_opts = " ".join(
                    [
                        "-i",
                        str(supervisor.private_key),
                        "-o",
                        "StrictHostKeyChecking=no",
                        "-o",
                        "UserKnownHostsFile=/dev/null",
                        "-o",
                        "BatchMode=yes",
                    ]
                )
                handle.ssh_run("echo admin | sudo -S rm -f /Applications/admin 2>/dev/null || true", timeout=20.0)
                for app_name in avail_apps:
                    _log(f"Streaming /Applications/{app_name} from osworld -> macarena...")
                    pipe_cmd = (
                        f"/usr/bin/ssh {ssh_opts} admin@{donor_handle.ip_address} "
                        f"\"tar -cf - -C /Applications '{app_name}'\" | "
                        f"/usr/bin/ssh {ssh_opts} admin@{handle.ip_address} "
                        "'cat > /tmp/app_sync.tar'"
                    )
                    res = subprocess.run(
                        ["/bin/bash", "-c", pipe_cmd],
                        capture_output=True,
                        text=True,
                        timeout=1800.0,
                        check=False,
                    )
                    if res.returncode != 0:
                        raise UTMSupervisorError(
                            f"Failed syncing {app_name} into macarena: {res.stderr[-400:]}"
                        )
                    handle.ssh_run(
                        f"echo admin | sudo -S rm -rf '/Applications/{app_name}' && "
                        "echo admin | sudo -S tar -xf /tmp/app_sync.tar -C /Applications && "
                        "rm -f /tmp/app_sync.tar && "
                        f"echo admin | sudo -S chown -R admin:admin '/Applications/{app_name}' && "
                        f"echo admin | sudo -S xattr -dr com.apple.quarantine '/Applications/{app_name}' 2>/dev/null || true",
                        timeout=300.0,
                    )
                    actions["syncedApps"].append(app_name)
            finally:
                supervisor.release_disposable_vm(donor_handle)

        macarena_seed_cmd = (
            "set -e; "
            "echo admin | sudo -S rm -f /Applications/admin 2>/dev/null || true; "
            "LSREG=\"/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister\"; "
            "for app in Keynote Numbers Pages LibreOffice; do "
            "  if [ -d \"/Applications/${app}.app\" ]; then "
            "    \"$LSREG\" -f \"/Applications/${app}.app\"; "
            "  fi; "
            "done; "
            "for bid in com.apple.iWork.Keynote com.apple.iWork.Numbers com.apple.iWork.Pages; do "
            "  defaults write ~/Library/Containers/${bid}/Data/Library/Preferences/${bid} TMAFirstLaunchVersion -int 999999 2>/dev/null || true; "
            "  defaults write ${bid} TMAFirstLaunchVersion -int 999999 2>/dev/null || true; "
            "done; "
            "for bid in com.apple.iWork.Keynote com.apple.iWork.Numbers com.apple.iWork.Pages org.libreoffice.script; do "
            "  open -Ra / -b \"$bid\"; "
            "done; "
            "mkdir -p ~/Documents/ResearchVault/.obsidian ~/Library/Application\\ Support/obsidian; "
            "echo admin | sudo -S chown -R admin:staff ~/Documents ~/Library/Application\\ Support/obsidian /Applications/Obsidian.app 2>/dev/null || true; "
            "xattr -dr com.apple.quarantine /Applications/Obsidian.app 2>/dev/null || true; "
            "printf '{\"vaults\":{\"2c4dba47bc79f875\":{\"path\":\"%s/Documents/ResearchVault\",\"ts\":%s,\"open\":true}}}' "
            "\"$HOME\" \"$(($(date +%s)*1000))\" > ~/Library/Application\\ Support/obsidian/obsidian.json; "
            "open -a Obsidian >/dev/null 2>&1 || true; "
            "sleep 6; "
            "osascript -e 'tell application \"Obsidian\" to quit' >/dev/null 2>&1 || pkill -f Obsidian || true; "
            "rm -rf ~/Documents/ResearchVault; "
            "osascript -e 'tell application \"Contacts\"\n"
            "  if (count of people) is 0 then\n"
            "    set p to make new person with properties {first name:\"Alex\", last name:\"Morgan\", organization:\"MacArena Lab\"}\n"
            "    make new email at end of emails of p with properties {label:\"work\", value:\"alex.morgan@example.com\"}\n"
            "    save\n"
            "  end if\n"
            "end tell' >/dev/null 2>&1 || true; "
            "osascript -e 'tell application \"Contacts\" to quit' >/dev/null 2>&1 || true"
        )
        handle.ssh_run(macarena_seed_cmd, timeout=120.0, check=False)
        actions["obsidianAndContactsSeeded"] = True

    if base_vm_name == "osworld":
        klee_py = (
            "import ctypes, ctypes.util\n"
            "ct = ctypes.cdll.LoadLibrary(ctypes.util.find_library('CoreText'))\n"
            "cf = ctypes.cdll.LoadLibrary(ctypes.util.find_library('CoreFoundation'))\n"
            "cf.CFStringCreateWithCString.restype = ctypes.c_void_p\n"
            "cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]\n"
            "ct.CTFontDescriptorCreateWithNameAndSize.restype = ctypes.c_void_p\n"
            "ct.CTFontDescriptorCreateWithNameAndSize.argtypes = [ctypes.c_void_p, ctypes.c_double]\n"
            "cf.CFArrayCreate.restype = ctypes.c_void_p\n"
            "cf.CFArrayCreate.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_long, ctypes.c_void_p]\n"
            "HANDLER = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_uint32, ctypes.c_void_p)\n"
            "done = {'ok': False}\n"
            "@HANDLER\n"
            "def cb(state, param):\n"
            "    if state in (1, 8):\n"
            "        done['ok'] = True\n"
            "    return True\n"
            "name_cf = cf.CFStringCreateWithCString(None, b'Klee-Medium', 0x08000100)\n"
            "desc = ct.CTFontDescriptorCreateWithNameAndSize(name_cf, 14.0)\n"
            "arr_vals = (ctypes.c_void_p * 1)(desc)\n"
            "arr = cf.CFArrayCreate(None, arr_vals, 1, None)\n"
            "ct.CTFontDescriptorMatchFontDescriptorsWithProgressHandler.restype = ctypes.c_bool\n"
            "ct.CTFontDescriptorMatchFontDescriptorsWithProgressHandler.argtypes = [ctypes.c_void_p, ctypes.c_void_p, HANDLER]\n"
            "res = ct.CTFontDescriptorMatchFontDescriptorsWithProgressHandler(arr, None, cb)\n"
            "print('KLEE_FONT_MATCH:', bool(res), done)\n"
        )
        klee_b64 = base64.b64encode(klee_py.encode("utf-8")).decode("ascii")
        osworld_seed_cmd = (
            f"echo '{klee_b64}' | base64 -d | python3 - || true; "
            "for bid in com.apple.iWork.Keynote com.apple.iWork.Numbers com.apple.iWork.Pages; do "
            "  defaults write ~/Library/Containers/${bid}/Data/Library/Preferences/${bid} TMAFirstLaunchVersion -int 999999 2>/dev/null || true; "
            "  defaults write ${bid} TMAFirstLaunchVersion -int 999999 2>/dev/null || true; "
            "done; "
            "osascript -e 'tell application \"Reminders\"\n"
            "  set matchingRems to (every reminder whose name is \"Call him\" or name is \"call him\")\n"
            "  if (count of matchingRems) is 0 then\n"
            "    tell default list to make new reminder with properties {name:\"Call him\", completed:false}\n"
            "  end if\n"
            "end tell' >/dev/null 2>&1 || true; "
            "osascript -e 'tell application \"Reminders\" to quit' >/dev/null 2>&1 || true"
        )
        seed_out = handle.ssh_run(osworld_seed_cmd, timeout=180.0, check=False).stdout.strip()
        actions["kleeAndRemindersSeeded"] = seed_out

    return actions


def _log(msg: str) -> None:
    print(f"[provision] {msg}", file=sys.stderr, flush=True)


def _read_vm_mac(bundle_dir: Path) -> str:
    plist_path = bundle_dir / "config.plist"
    with plist_path.open("rb") as fh:
        pl = plistlib.load(fh)
    return str(pl["Network"][0]["MacAddress"])


def _seed_ssh_key_with_expect(
    *,
    ip: str,
    pub_key_text: str,
    password: str = "admin",
    timeout: float = 60.0,
) -> None:
    remote_cmd = (
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
        f"grep -qxF '{pub_key_text.strip()}' ~/.ssh/authorized_keys 2>/dev/null || "
        f"echo '{pub_key_text.strip()}' >> ~/.ssh/authorized_keys && "
        "chmod 600 ~/.ssh/authorized_keys && echo KEY_INSTALLED_OK"
    )
    expect_script = f"""
set timeout 30
spawn /usr/bin/ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o PreferredAuthentications=password admin@{ip} "{remote_cmd}"
expect {{
    -re "(?i)password:" {{
        send "{password}\\r"
        exp_continue
    }}
    "KEY_INSTALLED_OK" {{
        expect eof
        exit 0
    }}
    timeout {{
        exit 2
    }}
    eof {{
        exit 0
    }}
}}
"""
    res = subprocess.run(
        ["/usr/bin/expect", "-c", expect_script],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if res.returncode != 0 and "KEY_INSTALLED_OK" not in res.stdout:
        raise UTMSupervisorError(
            f"Failed seeding SSH key onto {ip}: rc={res.returncode} out={res.stdout} err={res.stderr}"
        )


def import_utm_bundle_if_needed(
    *,
    source_bundle: Path,
    target_name: str,
    utm_documents_dir: Path = UTM_DOCUMENTS_DIR,
) -> Path:
    source_bundle = source_bundle.expanduser().resolve()
    if not (source_bundle / "config.plist").is_file():
        raise FileNotFoundError(f"Source UTM bundle incomplete: {source_bundle}")
    utm_documents_dir.mkdir(parents=True, exist_ok=True)
    dest_bundle = utm_documents_dir / f"{target_name}.utm"
    if not dest_bundle.exists():
        # APFS copy-on-write clone (`cp -cR`) takes <2s and consumes zero extra disk blocks!
        res = subprocess.run(
            ["/bin/cp", "-cR", str(source_bundle), str(dest_bundle)],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode != 0:
            shutil.copytree(source_bundle, dest_bundle)
    # Ensure Information.Name matches target_name so `utmctl` addresses it deterministically
    plist_path = dest_bundle / "config.plist"
    with plist_path.open("rb") as fh:
        pl = plistlib.load(fh)
    changed = False
    if pl.get("Information", {}).get("Name") != target_name:
        pl.setdefault("Information", {})["Name"] = target_name
        changed = True
    if pl.get("System", {}).get("CPUCount", 0) == 0:
        pl["System"]["CPUCount"] = 4
        changed = True
    if changed:
        with plist_path.open("wb") as fh:
            plistlib.dump(pl, fh)
    # Open bundle once in background with UTM so UTM registers it in its library list
    subprocess.run(
        ["/usr/bin/open", "-g", "-a", "/Applications/UTM.app", str(dest_bundle)],
        check=False,
        capture_output=True,
    )
    time.sleep(3.0)
    return dest_bundle


def build_eval_wheel(project_root: Path, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(out_dir)],
        cwd=str(project_root),
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = sorted(out_dir.glob("fsq_macarena_eval-*.whl"))
    if not wheels:
        raise RuntimeError(f"Failed building fsq_macarena_eval wheel in {out_dir}")
    return wheels[-1]


def prepare_offline_guest_wheelhouse(
    *,
    project_root: Path,
    wheelhouse_dir: Path,
    appium_wheel: Path,
    fsq_wheel: Path,
    eval_wheel: Path,
) -> Path:
    wheelhouse_dir.mkdir(parents=True, exist_ok=True)
    for stale_pattern in ("appium_connect_agent-*.whl", "fsq_agent-*.whl", "fsq_macarena_eval-*.whl"):
        for stale_whl in wheelhouse_dir.glob(stale_pattern):
            stale_whl.unlink(missing_ok=True)
    shutil.copy2(appium_wheel, wheelhouse_dir / appium_wheel.name)
    shutil.copy2(fsq_wheel, wheelhouse_dir / fsq_wheel.name)
    shutil.copy2(eval_wheel, wheelhouse_dir / eval_wheel.name)
    if len(list(wheelhouse_dir.glob("*.whl"))) < 15:
        _log("Caching offline Python 3.12 arm64 wheelhouse on host...")
        subprocess.run(
            [
                "uv",
                "run",
                "--with",
                "pip",
                "python",
                "-m",
                "pip",
                "download",
                "--dest",
                str(wheelhouse_dir),
                "--python-version",
                "3.12",
                "--platform",
                "macosx_14_0_arm64",
                "--only-binary=:all:",
                str(appium_wheel),
                str(fsq_wheel),
                str(eval_wheel),
            ],
            cwd=str(project_root),
            check=True,
            capture_output=True,
            text=True,
            timeout=300.0,
        )
    return wheelhouse_dir

def provision_golden_vm(
    *,
    base_vm_name: str,
    source_bundle: Path | None,
    macarena_repo: Path,
    project_root: Path,
    supervisor: DualSlotUTMSupervisor,
    xcode_donor_bundle: Path | None = None,
    appium_connect_wheel: Path | None = None,
    fsq_agent_wheel: Path | None = None,
    host_fsq_config_dir: Path = Path("~/.fsq").expanduser(),
) -> dict[str, Any]:
    """Import (or upgrade in-place), provision Aqua TCC + apps + wheels, verify WDA + model probe, and shut down."""
    appium_spec, fsq_spec = default_frozen_wheels(
        appium_connect_wheel=appium_connect_wheel,
        fsq_agent_wheel=fsq_agent_wheel,
    )
    if appium_connect_wheel is not None:
        from .manifest import FrozenWheelSpec, file_sha256

        appium_spec = FrozenWheelSpec(
            package_name="appium-connect-agent",
            version=appium_spec.version,
            path=appium_connect_wheel.expanduser().resolve(),
            expected_sha256=file_sha256(appium_connect_wheel.expanduser().resolve()),
            source_commit=appium_spec.source_commit,
        )
    if fsq_agent_wheel is not None:
        from .manifest import FrozenWheelSpec, file_sha256

        fsq_spec = FrozenWheelSpec(
            package_name="fsq-agent",
            version=fsq_spec.version,
            path=fsq_agent_wheel.expanduser().resolve(),
            expected_sha256=file_sha256(fsq_agent_wheel.expanduser().resolve()),
            source_commit=fsq_spec.source_commit,
        )
    wheel_manifest = verify_frozen_wheels((appium_spec, fsq_spec))
    appium_wheel, fsq_wheel = appium_spec, fsq_spec
    eval_wheel = build_eval_wheel(project_root, supervisor.state_dir / "built_wheels")

    existing_golden = supervisor.utm_documents_dir / f"{base_vm_name}.utm"
    effective_source = source_bundle if source_bundle is not None else existing_golden
    dest_bundle = import_utm_bundle_if_needed(
        source_bundle=effective_source,
        target_name=base_vm_name,
        utm_documents_dir=supervisor.utm_documents_dir,
    )
    mac_address = _read_vm_mac(dest_bundle)
    _log(f"Imported {base_vm_name} at {dest_bundle} (MAC={mac_address}); starting VM...")

    # Stop if already running, then boot base VM directly to bake Golden state
    st = run_utmctl(["status", base_vm_name], check=False, hide=True)
    if "started" in st.stdout.lower() or "running" in st.stdout.lower():
        pass
    else:
        run_utmctl(["start", base_vm_name], hide=True, timeout=60.0)

    ip = resolve_guest_ip(base_vm_name, mac_address, timeout_seconds=150.0)
    pub_key_text = supervisor.public_key.read_text(encoding="utf-8").strip()
    _log(f"{base_vm_name} resolved guest IP={ip}; ensuring SSH key...")

    # Try key auth first; if not yet seeded, seed with expect (`admin`/`admin`)
    try:
        supervisor.wait_for_ssh(ip, timeout_seconds=12.0)
    except UTMSupervisorError:
        _seed_ssh_key_with_expect(ip=ip, pub_key_text=pub_key_text)
        supervisor.wait_for_ssh(ip, timeout_seconds=60.0)

    handle = ClonedVMHandle(
        slot_id=0,
        base_vm_name=base_vm_name,
        vm_name=base_vm_name,
        mac_address=mac_address,
        ip_address=ip,
        private_key=supervisor.private_key,
    )
    supervisor._start_reverse_proxy_tunnel_if_available(handle)
    _log(f"SSH key ready on {ip}; reverse proxy tunnel={handle.guest_proxy_url}")
    proxy_exports = ""
    if handle.guest_proxy_url:
        proxy_exports = (
            f"export HTTP_PROXY={handle.guest_proxy_url} "
            f"HTTPS_PROXY={handle.guest_proxy_url} "
            f"ALL_PROXY={handle.guest_proxy_url} "
            "NO_PROXY=127.0.0.1,localhost,::1; "
        )

    try:
        # 1. Inspect guest OS, Xcode, Node, Conda, Python
        guest_facts = handle.ssh_run(
            "sw_vers; uname -m; df -h /; "
            "ls -ld /Applications/Xcode.app 2>/dev/null || echo NO_XCODE_APP; "
            "xcode-select -p 2>/dev/null || true; "
            "PATH=/opt/homebrew/bin:/usr/local/bin:$PATH command -v node npm python3 brew 2>/dev/null || true",
            timeout=30.0,
        ).stdout

        _log(f"Guest facts:\n{guest_facts.strip()}")
        _log("Uploading vm_files and pre-baking Conda server environment...")
        # 2. Upload MacArena `vm_files` and start `allow_permission.sh` + Conda `server` env setup
        handle.scp_to_guest(macarena_repo / "vm_files", "/Users/admin/", recursive=True, timeout=180.0)
        handle.ssh_run(
            "nohup bash -lc 'chmod +x ~/vm_files/allow_permission.sh && ~/vm_files/allow_permission.sh' > ~/allow.log 2>&1 < /dev/null &",
            timeout=20.0,
        )

        # Pre-bake MacArena server conda env + packages (without blocking on main.py)
        osworld_tools_dir = supervisor.state_dir / "osworld_tools_wheelhouse"
        if osworld_tools_dir.is_dir() and list(osworld_tools_dir.glob("*.whl")):
            handle.ssh_run("rm -rf /Users/admin/.osworld-tools-wheels && mkdir -p /Users/admin/.osworld-tools-wheels", timeout=15.0)
            handle.scp_to_guest(osworld_tools_dir, "/Users/admin/.osworld-tools-wheels", recursive=True, timeout=180.0)
        conda_setup_cmd = (
            f"{proxy_exports}"
            "export PATH=/opt/homebrew/bin:/usr/local/bin:$PATH; "
            "echo admin | sudo -S mdutil -a -i on >/dev/null 2>&1 || true; "
            "if [ ! -d /opt/homebrew/Caskroom/miniconda/base/envs/server ]; then "
            "  /opt/homebrew/Caskroom/miniconda/base/bin/conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main >/dev/null 2>&1 || true; "
            "  /opt/homebrew/Caskroom/miniconda/base/bin/conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r >/dev/null 2>&1 || true; "
            "  /opt/homebrew/Caskroom/miniconda/base/bin/conda env create -f ~/vm_files/server/environment.yml -n server --yes; "
            "fi; "
            "command -v ffmpeg >/dev/null 2>&1 || HOMEBREW_NO_AUTO_UPDATE=1 brew install ffmpeg || true; "
            "TOOLS_WHL=/Users/admin/.osworld-tools-wheels/osworld_tools_wheelhouse; "
            "[ -d \"$TOOLS_WHL\" ] || TOOLS_WHL=/Users/admin/.osworld-tools-wheels; "
            "if [ -d \"$TOOLS_WHL\" ] && ls \"$TOOLS_WHL\"/*.whl >/dev/null 2>&1; then "
            "  python3 -m pip install --break-system-packages --no-index --find-links \"$TOOLS_WHL\" pyautogui pillow PyPDF2 pycocoa PyMuPDF opencv-python >/dev/null 2>&1 || true; "
            "fi; "
            "rm -rf /Users/admin/.osworld-tools-wheels"
        )
        handle.ssh_run(conda_setup_cmd, timeout=300.0)
        _log("Conda server environment ready; checking /Applications/Xcode*.app...")
        # 3. Ensure Xcode*.app is installed and selected in guest (required by appium-connect-agent + Mac2 WDA)
        detect_xcode_cmd = (
            "python3 -c 'from pathlib import Path; "
            "cands = sorted(p for p in Path(\"/Applications\").glob(\"Xcode*.app\") "
            "if p.is_dir() and not p.is_symlink() and (p / \"Contents/Developer/usr/bin/xcodebuild\").is_file()); "
            "print(str(cands[-1]) if cands else \"\")'"
        )
        xcode_app_path = handle.ssh_run(detect_xcode_cmd, timeout=15.0).stdout.strip()
        if not xcode_app_path:
            donor_vm_name = "macarena" if base_vm_name != "macarena" else None
            donor_bundle = (
                supervisor.utm_documents_dir / f"{donor_vm_name}.utm"
                if donor_vm_name is not None
                else None
            )
            if donor_bundle is None or not donor_bundle.is_dir():
                raise UTMSupervisorError(
                    f"{base_vm_name} lacks /Applications/Xcode*.app and donor Golden VM 'macarena' is not available"
                )
            _log(f"{base_vm_name} lacks Xcode*.app; booting donor 'macarena' on slot 1 to stream Xcode...")
            donor_handle = supervisor.acquire_disposable_vm(
                slot_id=1,
                base_vm_name="macarena",
                task_id="xcode-donor-transfer",
            )
            try:
                donor_xcode = donor_handle.ssh_run(detect_xcode_cmd, timeout=15.0).stdout.strip()
                if not donor_xcode:
                    raise UTMSupervisorError("Donor VM 'macarena' also lacks /Applications/Xcode*.app")
                donor_xcode_name = Path(donor_xcode).name
                _log(f"Streaming {donor_xcode_name} from donor {donor_handle.ip_address} -> {handle.ip_address}...")
                ssh_pipe_cmd = [
                    "/bin/bash",
                    "-c",
                    f"/usr/bin/ssh {' '.join(str(x) for x in [ '-i', str(supervisor.private_key), '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'BatchMode=yes' ])} "
                    f"admin@{donor_handle.ip_address} 'tar -cf - -C /Applications {donor_xcode_name}' | "
                    f"/usr/bin/ssh {' '.join(str(x) for x in [ '-i', str(supervisor.private_key), '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'BatchMode=yes' ])} "
                    f"admin@{handle.ip_address} 'echo admin | sudo -S tar -xf - -C /Applications'",
                ]
                pipe_res = subprocess.run(
                    ssh_pipe_cmd,
                    capture_output=True,
                    text=True,
                    timeout=1800.0,
                    check=False,
                )
                if pipe_res.returncode != 0:
                    raise UTMSupervisorError(
                        f"Streaming {donor_xcode_name} from donor VM failed: {pipe_res.stderr[-500:]}"
                    )
                xcode_app_path = f"/Applications/{donor_xcode_name}"
            finally:
                supervisor.release_disposable_vm(donor_handle)

        handle.ssh_run(
            f"echo admin | sudo -S xcode-select -s {xcode_app_path}/Contents/Developer && "
            "(echo admin | sudo -S xcodebuild -license accept >/dev/null 2>&1 || true) && "
            "(echo admin | sudo -S DevToolsSecurity -enable >/dev/null 2>&1 || true) && "
            "echo admin | sudo -S automationmodetool enable-automationmode-without-authentication && "
            "(echo admin | sudo -S killall -9 testmanagerd automationmode-writer 2>/dev/null || true)",
            timeout=120.0,
        )
        _log(f"Xcode configured ({xcode_app_path}); ensuring Node >= 20 via Homebrew...")

        # 4. Ensure Node >= 20.19 / 22+ & npm >= 10 inside guest (using cached official darwin-arm64 tarball when absent!)
        has_node20 = handle.ssh_run(
            "export PATH=/opt/homebrew/bin:/usr/local/bin:$PATH; "
            "command -v node >/dev/null 2>&1 && node -e 'process.exit(parseInt(process.versions.node.split(\".\")[0],10)>=20?0:1)' && echo READY || echo MISSING",
            check=False,
            timeout=15.0,
        ).stdout.strip()
        if "READY" not in has_node20:
            node_tar = supervisor.state_dir / "node_cache" / "node-v22.18.0-darwin-arm64.tar.gz"
            if not node_tar.is_file():
                node_tar.parent.mkdir(parents=True, exist_ok=True)
                subprocess.run(
                    ["/usr/bin/curl", "-fsSL", "https://nodejs.org/dist/v22.18.0/node-v22.18.0-darwin-arm64.tar.gz", "-o", str(node_tar)],
                    check=True,
                    timeout=180.0,
                )
            handle.scp_to_guest(node_tar, "/tmp/node-arm64.tar.gz", timeout=60.0)
            handle.ssh_run(
                "echo admin | sudo -S mkdir -p /usr/local/lib/nodejs /usr/local/bin && "
                "echo admin | sudo -S rm -rf /usr/local/lib/nodejs/node-v22.18.0-darwin-arm64 && "
                "echo admin | sudo -S tar -xzf /tmp/node-arm64.tar.gz -C /usr/local/lib/nodejs && "
                "echo admin | sudo -S ln -sf /usr/local/lib/nodejs/node-v22.18.0-darwin-arm64/bin/node /usr/local/bin/node && "
                "echo admin | sudo -S ln -sf /usr/local/lib/nodejs/node-v22.18.0-darwin-arm64/bin/npm /usr/local/bin/npm && "
                "echo admin | sudo -S ln -sf /usr/local/lib/nodejs/node-v22.18.0-darwin-arm64/bin/npx /usr/local/bin/npx && "
                "rm -f /tmp/node-arm64.tar.gz",
                timeout=60.0,
            )
        handle.ssh_run(
            "export PATH=/opt/homebrew/bin:/usr/local/bin:$PATH; node -v && npm -v",
            timeout=20.0,
        )
        _log("Node/npm ready; creating isolated ~/.fsq-eval-venv with frozen wheels...")

        # 5. Upload offline wheelhouse, create isolated `~/.fsq-eval-venv`, install non-editable wheels offline in seconds!
        wheelhouse_dir = prepare_offline_guest_wheelhouse(
            project_root=project_root,
            wheelhouse_dir=supervisor.state_dir / "guest_wheelhouse",
            appium_wheel=appium_wheel.path,
            fsq_wheel=fsq_wheel.path,
            eval_wheel=eval_wheel,
        )
        handle.ssh_run("rm -rf /Users/admin/.fsq-wheels && mkdir -p /Users/admin/.fsq-wheels", timeout=20.0)
        handle.scp_to_guest(wheelhouse_dir, "/Users/admin/.fsq-wheels", recursive=True, timeout=180.0)

        venv_cmd = (
            "export PATH=/opt/homebrew/bin:/usr/local/bin:$PATH; "
            "PY_BIN=$(command -v python3.12 || command -v python3.11 || echo /opt/homebrew/Caskroom/miniconda/base/envs/server/bin/python3); "
            "rm -rf /Users/admin/.fsq-eval-venv; "
            "\"$PY_BIN\" -m venv /Users/admin/.fsq-eval-venv; "
            "WHEEL_DIR=/Users/admin/.fsq-wheels/guest_wheelhouse; "
            "[ -d \"$WHEEL_DIR\" ] || WHEEL_DIR=/Users/admin/.fsq-wheels; "
            "/Users/admin/.fsq-eval-venv/bin/pip install --no-index --find-links \"$WHEEL_DIR\" "
            f"\"$WHEEL_DIR/{appium_wheel.path.name}\" "
            f"\"$WHEEL_DIR/{fsq_wheel.path.name}\" "
            f"\"$WHEEL_DIR/{eval_wheel.name}\""
        )
        handle.ssh_run(venv_cmd, timeout=180.0)
        _log("Frozen wheels installed offline; seeding managed Appium 3.7.0 + Mac2 4.6.1...")

        # 6. Seed host's verified `~/.appium-connect-agent` (Appium 3.7.0 + Mac2 4.6.1) if available, then verify via Runtime API!
        host_aca_root = Path("~/.appium-connect-agent").expanduser()
        if (host_aca_root / "managed.json").is_file():
            ssh_base = " ".join(
                str(x)
                for x in [
                    "-i",
                    str(supervisor.private_key),
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "BatchMode=yes",
                ]
            )
            host_home_str = str(host_aca_root.parent)
            seed_cmd = (
                f"/usr/bin/tar -cf - -C {host_home_str} .appium-connect-agent | "
                f"/usr/bin/ssh {ssh_base} admin@{handle.ip_address} "
                "'rm -rf /Users/admin/.appium-connect-agent && tar -xf - -C /Users/admin && "
                "rm -f /Users/admin/.appium-connect-agent/records/service.json && "
                "chown -R admin:staff /Users/admin/.appium-connect-agent && "
                "chmod 700 /Users/admin/.appium-connect-agent && "
                "chmod -R go-w /Users/admin/.appium-connect-agent'"
            )
            seed_res = subprocess.run(
                ["/bin/bash", "-c", seed_cmd],
                capture_output=True,
                text=True,
                timeout=300.0,
                check=False,
            )
            if seed_res.returncode != 0:
                _log(f"Warning: host ~/.appium-connect-agent stream returned {seed_res.returncode}: {seed_res.stderr[:200]}")
            relocate_py = (
                "import os\n"
                "from pathlib import Path\n"
                f"old_prefix = {host_home_str!r} + '/'\n"
                "new_prefix = '/Users/admin/'\n"
                "root = Path('/Users/admin/.appium-connect-agent')\n"
                "ext_yaml = root / 'driver-home/node_modules/.cache/appium/extensions.yaml'\n"
                "if ext_yaml.is_file():\n"
                "    ext_yaml.write_text(ext_yaml.read_text(encoding='utf-8').replace(old_prefix, new_prefix), encoding='utf-8')\n"
                "for dirpath, dirnames, filenames in os.walk(root, followlinks=False):\n"
                "    for name in list(dirnames) + list(filenames):\n"
                "        p = Path(dirpath) / name\n"
                "        if p.is_symlink():\n"
                "            target = os.readlink(p)\n"
                "            if old_prefix in target:\n"
                "                new_target = target.replace(old_prefix, new_prefix)\n"
                "                p.unlink()\n"
                "                p.symlink_to(new_target)\n"
            )
            reloc_b64 = base64.b64encode(relocate_py.encode("utf-8")).decode("ascii")
            handle.ssh_run(
                f"echo '{reloc_b64}' | base64 -d | /Users/admin/.fsq-eval-venv/bin/python -",
                timeout=60.0,
            )
        runtime_setup_py = (
            "from pathlib import Path\n"
            "from appium_connect_agent.contracts import LocalSettings\n"
            "from appium_connect_agent.runtime import InstallRequest, OperationControl, Runtime\n"
            "import shutil\n"
            "node = Path(shutil.which('node')).resolve()\n"
            "npm = Path(shutil.which('npm')).resolve()\n"
            "rt = Runtime(LocalSettings(node_executable=node, npm_executable=npm))\n"
            "diag = rt.diagnose(target_driver='mac2', control=OperationControl(timeout_seconds=120.0))\n"
            "by_id = {c.check_id: c for c in diag.checks}\n"
            "if any(by_id[k].status != 'pass' for k in ('managed_root', 'appium_installation', 'driver_installation')):\n"
            "    ins = rt.install(InstallRequest(), control=OperationControl(timeout_seconds=600.0))\n"
            "    drv = rt.ensure_managed_driver('mac2', control=OperationControl(timeout_seconds=600.0))\n"
            "    diag = rt.diagnose(target_driver='mac2', control=OperationControl(timeout_seconds=120.0))\n"
            "for c in diag.checks:\n"
            "    print('CHECK:', c.check_id, c.status, c.reason_code)\n"
            "    if c.check_id in ('managed_root', 'appium_installation', 'driver_installation', 'xcode_layout', 'node_candidate', 'npm_candidate') and c.status != 'pass':\n"
            "        raise RuntimeError(f'Diagnostic check failed: {c.check_id}={c.status} ({c.reason_code})')\n"
            "with rt.start_managed(host='127.0.0.1', port=4731, base_path='', control=OperationControl(timeout_seconds=60.0)) as conn:\n"
            "    print('MANAGED_APPIUM_OK:', conn.server_url)\n"
        )
        rt_b64 = base64.b64encode(runtime_setup_py.encode("utf-8")).decode("ascii")
        rt_out = handle.ssh_run(
            f"{proxy_exports}"
            "export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; "
            f"echo '{rt_b64}' | base64 -d | /Users/admin/.fsq-eval-venv/bin/python -",
            timeout=900.0,
        ).stdout
        _log(f"Managed Appium + Mac2 verified:\n{rt_out.strip()}\nPre-compiling WebDriverAgentMac...")

        # Pre-compile WebDriverAgentMac so first task session creation doesn't spend 90s compiling!
        wda_prebuild_cmd = (
            "export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; "
            "WDA_DIR=/Users/admin/.appium-connect-agent/driver-home/node_modules/appium-mac2-driver/WebDriverAgentMac; "
            "cd \"$WDA_DIR\" && "
            "xcodebuild build-for-testing -project WebDriverAgentMac.xcodeproj -scheme WebDriverAgentRunner -destination 'platform=macOS,arch=arm64' COMPILER_INDEX_STORE_ENABLE=NO | tail -n 20"
        )
        handle.ssh_run(wda_prebuild_cmd, timeout=900.0)
        _log("WebDriverAgentMac pre-built; syncing ~/.fsq auth & running live WDA Finder smoke...")

        # 7. Seed host `~/.fsq` provider config & auth directory into guest `~/.fsq` (chmod 700/600)
        handle.ssh_run("mkdir -p /Users/admin/.fsq/auth && chmod 700 /Users/admin/.fsq /Users/admin/.fsq/auth", timeout=15.0)
        src_cfg = host_fsq_config_dir / "config.yaml"
        if src_cfg.is_file():
            handle.scp_to_guest(src_cfg, "/Users/admin/.fsq/config.yaml", timeout=30.0)
            handle.ssh_run("chmod 600 /Users/admin/.fsq/config.yaml", timeout=15.0)
        src_auth_dir = host_fsq_config_dir / "auth"
        if src_auth_dir.is_dir():
            for auth_item in sorted(src_auth_dir.glob("*.json")):
                handle.scp_to_guest(auth_item, f"/Users/admin/.fsq/auth/{auth_item.name}", timeout=30.0)
            handle.ssh_run("chmod 600 /Users/admin/.fsq/auth/*.json 2>/dev/null || true", timeout=15.0)
        # 8. Live WDA Finder session smoke + native_model_probe inside guest
        wda_smoke_py = (
            "from pathlib import Path\n"
            "import shutil\n"
            "from appium_connect_agent.automation import create_mac2_session\n"
            "from appium_connect_agent.contracts import LocalSettings\n"
            "from appium_connect_agent.runtime import OperationControl, Runtime\n"
            "node = Path(shutil.which('node')).resolve()\n"
            "npm = Path(shutil.which('npm')).resolve()\n"
            "rt = Runtime(LocalSettings(node_executable=node, npm_executable=npm))\n"
            "with rt.start_managed(host='127.0.0.1', port=4729, base_path='', control=OperationControl(timeout_seconds=60.0)) as conn:\n"
            f"    sess = create_mac2_session(conn, bundle_id={INITIAL_BUNDLE_ID!r}, no_reset=True, control=OperationControl(timeout_seconds=90.0))\n"
            "    try:\n"
            "        tree = sess.observe_tree(control=OperationControl(timeout_seconds=30.0))\n"
            "        png = sess.device.take_screenshot(control=OperationControl(timeout_seconds=30.0))\n"
            "        print('WDA_FINDER_OK:', type(tree).__name__, 'png_bytes=', len(png))\n"
            "    finally:\n"
            "        sess.quit(control=OperationControl(timeout_seconds=20.0))\n"
        )
        wda_b64 = base64.b64encode(wda_smoke_py.encode("utf-8")).decode("ascii")
        wda_out = handle.ssh_run(
            "export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; "
            f"echo '{wda_b64}' | base64 -d | /Users/admin/.fsq-eval-venv/bin/python -",
            timeout=240.0,
        ).stdout
        _log(f"Live WDA Finder smoke passed: {wda_out.strip()}; running native_model_probe...")

        probe_cmd = (
            f"{proxy_exports}"
            "export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; "
            "/Users/admin/.fsq-eval-venv/bin/python -m fsq_macarena_eval.fsq_worker probe "
            f"--provider {FROZEN_PROVIDER} --model {FROZEN_MODEL} "
            "--output /Users/admin/native-model-probe.json && "
            "cat /Users/admin/native-model-probe.json"
        )
        probe_raw = handle.ssh_run(probe_cmd, timeout=120.0).stdout
        probe_receipt = json.loads(probe_raw)
        if probe_receipt.get("status") != "passed_native_responses":
            raise UTMSupervisorError(f"Guest native_model_probe did not pass: {probe_receipt}")
        _log(f"native_model_probe passed: {probe_receipt.get('status')}; seeding Aqua LaunchAgent + TCC + fixtures...")

        aqua_tcc_receipt = configure_guest_aqua_launchagent_and_tcc(handle, supervisor)
        fixture_receipt = seed_guest_benchmark_fixtures_and_apps(
            base_vm_name=base_vm_name,
            handle=handle,
            supervisor=supervisor,
        )
        # Re-verify hard Aqua TCC gate after fixture seeding so final Golden state is 100% proven
        final_tcc_gate = supervisor.verify_guest_aqua_tcc_readiness(handle, timeout_seconds=45.0)
        aqua_tcc_receipt["finalPostSeedTccGate"] = final_tcc_gate

        # Clean temporary runtime logs before freezing Golden Base VM (keep com.fsq.macarena-server.plist enabled for boot!)
        handle.ssh_run(
            "pkill -9 -f 'appium' || true; "
            "rm -f /Users/admin/.appium-connect-agent/records/service.json "
            "/Users/admin/native-model-probe.json /tmp/test_appium.log; "
            "sync",
            check=False,
            timeout=20.0,
        )
    finally:
        for proc_attr in ("proxy_tunnel_proc", "host_forward_proc"):
            proc = getattr(handle, proc_attr, None)
            if proc is not None:
                proc.terminate()
                setattr(handle, proc_attr, None)
        with subprocess.Popen(
            [
                "/usr/bin/ssh",
                "-i",
                str(supervisor.private_key),
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                f"admin@{handle.ip_address}",
                "echo admin | sudo -S shutdown -h now >/dev/null 2>&1 || true",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ) as shut_proc:
            try:
                shut_proc.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                shut_proc.kill()
        for idx in range(45):
            st = run_utmctl(["status", base_vm_name], check=False, hide=True, timeout=10.0)
            if "stopped" in st.stdout.lower():
                break
            if idx == 20:
                run_utmctl(["stop", base_vm_name], check=False, hide=True, timeout=30.0)
            time.sleep(2.0)

    receipt = {
        "schemaVersion": 2,
        "baseVmName": base_vm_name,
        "utmBundlePath": str(dest_bundle),
        "frozenWheels": wheel_manifest,
        "guestFacts": guest_facts.strip(),
        "wdaFinderSmoke": wda_out.strip(),
        "nativeModelCall": probe_receipt,
        "aquaTccReadiness": aqua_tcc_receipt,
        "fixtureSeedReceipt": fixture_receipt,
        "completedAtUnix": time.time(),
    }
    receipt_path = supervisor.state_dir / f"golden-readiness-{base_vm_name}.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def bake_both_golden_vms_in_place(
    *,
    targets: tuple[str, ...] = ("osworld", "macarena"),
    macarena_repo: Path,
    project_root: Path,
    supervisor: DualSlotUTMSupervisor,
    appium_connect_wheel: Path | None = None,
    fsq_agent_wheel: Path | None = None,
    host_fsq_config_dir: Path = Path("~/.fsq").expanduser(),
) -> dict[str, Any]:
    """One-shot upgrade of `osworld.utm` then `macarena.utm` inside `vm_golden/`."""
    results: dict[str, Any] = {}
    for vm_name in targets:
        bundle_path = supervisor.utm_documents_dir / f"{vm_name}.utm"
        if not bundle_path.is_dir():
            fallback_cache = project_root / "vm_cache" / (
                "MacArena.utm" if vm_name == "macarena" else "osworld.utm"
            )
            source = fallback_cache if fallback_cache.is_dir() else bundle_path
        else:
            source = bundle_path
        results[vm_name] = provision_golden_vm(
            base_vm_name=vm_name,
            source_bundle=source,
            macarena_repo=macarena_repo,
            project_root=project_root,
            supervisor=supervisor,
            appium_connect_wheel=appium_connect_wheel,
            fsq_agent_wheel=fsq_agent_wheel,
            host_fsq_config_dir=host_fsq_config_dir,
        )
    return {"schemaVersion": 2, "upgradedGoldenVms": results}
