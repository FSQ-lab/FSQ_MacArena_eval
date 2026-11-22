"""Race-free UTM Golden VM & Dual-Slot Supervisor for MacArena.

Fixes upstream `UTMProvider`'s concurrent race conditions:
1. Never mutates the base Golden VM's `config.plist` before cloning.
2. Serializes `utmctl clone` with a host file lock, patches ONLY the cloned VM's
   `config.plist` (`MacAddress` and deterministic slot `ECID` inside `MacPlatform.MachineIdentifier`
   so Apple Virtualization.framework permits 2 concurrent macOS VMs without ECID collision),
   and boots each slot independently.
3. Uses Ed25519 SSH key auth (`StrictHostKeyChecking=no`, `BatchMode=yes`) + optional
   reverse proxy tunnel (`ssh -N -R 127.0.0.1:17877:127.0.0.1:<host_proxy_port>`) when a host
   HTTP proxy is active, while keeping direct connectivity when Clash TUN / direct network is active.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import os
import plistlib
import random
import re
import socket
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

from filelock import FileLock

UTM_DOCUMENTS_DIR = Path(__file__).resolve().parents[2] / "vm_golden"
SLOT_ECIDS: dict[int, int] = {
    0: 1125658967400250504,
    1: 2251317934800501009,
}

AQUA_LAUNCHAGENT_LABEL = "com.fsq.macarena-server"
AQUA_LAUNCHAGENT_REL_PATH = "Library/LaunchAgents/com.fsq.macarena-server.plist"


class UTMSupervisorError(RuntimeError):
    """Raised on UTM lifecycle, IP resolution, or SSH failure."""


def resolve_utmctl_binary() -> str:
    env_bin = os.environ.get("UTMCTL_BIN")
    if env_bin and Path(env_bin).is_file():
        return env_bin
    for candidate in (
        "/opt/homebrew/bin/utmctl",
        "/usr/local/bin/utmctl",
        "/Applications/UTM.app/Contents/MacOS/utmctl",
    ):
        if Path(candidate).is_file():
            return candidate
    raise UTMSupervisorError("utmctl binary not found; install UTM.app first")


def run_utmctl(
    args: list[str],
    *,
    check: bool = True,
    hide: bool = True,
    timeout: float = 120.0,
) -> subprocess.CompletedProcess[str]:
    cmd = [resolve_utmctl_binary(), *args]
    if hide and args and args[0] == "start":
        cmd.append("--hide")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if check and result.returncode != 0:
        raise UTMSupervisorError(
            f"utmctl {' '.join(args)} failed (rc={result.returncode}): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    return result


def generate_slot_mac(slot_id: int) -> str:
    """Locally-administered unicast MAC encoding slot_id in the second octet."""
    first = 0x02
    second = (0xA0 | (slot_id & 0x0F)) & 0xFF
    rest = [random.randint(0x00, 0xFF) for _ in range(4)]
    return ":".join(f"{b:02x}" for b in [first, second, *rest])


def patch_cloned_vm_config_plist(
    config_plist_path: Path,
    *,
    vm_name: str,
    mac_address: str,
    slot_id: int,
    cpu_count: int = 4,
    memory_mb: int = 8192,
) -> dict[str, Any]:
    """Patch ONLY a cloned VM's config.plist (MAC, Name, UUID, ECID, CPU/RAM)."""
    if not config_plist_path.is_file():
        raise FileNotFoundError(f"Cloned VM config.plist not found: {config_plist_path}")
    with config_plist_path.open("rb") as fh:
        plist = plistlib.load(fh)

    if "Information" in plist and isinstance(plist["Information"], dict):
        plist["Information"]["Name"] = vm_name
        plist["Information"]["UUID"] = str(uuid.uuid4()).upper()

    network = plist.get("Network")
    if not isinstance(network, list) or not network:
        raise UTMSupervisorError(f"Missing Network[0] in {config_plist_path}")
    network[0]["MacAddress"] = mac_address

    ecid = SLOT_ECIDS.get(slot_id, SLOT_ECIDS[0] + slot_id + 100)
    system = plist.get("System")
    if isinstance(system, dict):
        system["CPUCount"] = cpu_count
        system["MemorySize"] = memory_mb
        mac_platform = system.get("MacPlatform")
        if isinstance(mac_platform, dict) and isinstance(
            mac_platform.get("MachineIdentifier"), (bytes, bytearray)
        ):
            ident = plistlib.loads(mac_platform["MachineIdentifier"])
            if isinstance(ident, dict) and "ECID" in ident:
                ident["ECID"] = ecid
                mac_platform["MachineIdentifier"] = plistlib.dumps(
                    ident, fmt=plistlib.FMT_BINARY
                )

    with config_plist_path.open("wb") as fh:
        plistlib.dump(plist, fh)

    return {
        "vmName": vm_name,
        "macAddress": mac_address,
        "slotId": slot_id,
        "ecid": ecid,
        "cpuCount": cpu_count,
        "memorySizeMb": memory_mb,
    }


def _normalize_mac(mac: str) -> str:
    return ":".join(part.lstrip("0") or "0" for part in mac.lower().split(":"))


def lookup_dhcp_ip_for_mac(
    mac_address: str,
    *,
    leases_path: Path = Path("/var/db/dhcpd_leases"),
) -> str | None:
    if not leases_path.is_file():
        return None
    norm = _normalize_mac(mac_address)
    content = leases_path.read_text(encoding="utf-8", errors="replace")
    best_ip: str | None = None
    best_ts = -1
    for block in content.split("{"):
        if f"hw_address=1,{norm}" not in block.lower():
            continue
        ip_m = re.search(r"ip_address=(\S+)", block)
        ts_m = re.search(r"lease=(0x[0-9a-fA-F]+)", block)
        if not ip_m:
            continue
        ts = int(ts_m.group(1), 16) if ts_m else 0
        if ts >= best_ts:
            best_ts = ts
            best_ip = ip_m.group(1).strip()
    return best_ip


def lookup_arp_ip_for_mac(mac_address: str) -> str | None:
    norm = _normalize_mac(mac_address)
    res = subprocess.run(
        ["/usr/sbin/arp", "-an"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    for line in res.stdout.splitlines():
        ip_m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
        mac_m = re.search(r"at ([0-9a-fA-F:]+)", line)
        if ip_m and mac_m and _normalize_mac(mac_m.group(1)) == norm:
            return ip_m.group(1)
    return None


def resolve_guest_ip(
    vm_name: str,
    mac_address: str,
    *,
    timeout_seconds: float = 120.0,
) -> str:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            out = run_utmctl(["ip-address", vm_name], check=False, timeout=10.0)
            for line in out.stdout.splitlines():
                candidate = line.strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", candidate):
                    return candidate
        except Exception:
            pass
        ip = lookup_dhcp_ip_for_mac(mac_address) or lookup_arp_ip_for_mac(mac_address)
        if ip:
            return ip
        time.sleep(2.0)
    raise UTMSupervisorError(
        f"Timed out resolving guest IP for VM {vm_name!r} (MAC {mac_address})"
    )


def is_tcp_port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False



def pick_ephemeral_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])

def ensure_ssh_keypair(key_dir: Path) -> tuple[Path, Path]:
    key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    priv = key_dir / "id_ed25519"
    pub = key_dir / "id_ed25519.pub"
    if not priv.is_file() or not pub.is_file():
        subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "fsq-macarena-eval",
                "-f",
                str(priv),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    os.chmod(priv, 0o600)
    return priv, pub


def build_ssh_base_args(private_key: Path) -> list[str]:
    return [
        "-i",
        str(private_key),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=4",
    ]


@dataclasses.dataclass
class ClonedVMHandle:
    slot_id: int
    base_vm_name: str
    vm_name: str
    mac_address: str
    ip_address: str
    private_key: Path
    user: str = "admin"
    proxy_tunnel_proc: subprocess.Popen[str] | None = None
    guest_proxy_url: str | None = None
    host_forward_proc: subprocess.Popen[str] | None = None
    host_server_port: int = 5000
    host_chromium_port: int = 9222
    host_vlc_port: int = 8080
    tcc_readiness_receipt: dict[str, Any] | None = None

    def ssh_run(
        self,
        remote_cmd: str,
        *,
        timeout: float = 120.0,
        check: bool = True,
        retries: int = 2,
    ) -> subprocess.CompletedProcess[str]:
        cmd = [
            "/usr/bin/ssh",
            *build_ssh_base_args(self.private_key),
            f"{self.user}@{self.ip_address}",
            remote_cmd,
        ]
        last_exc: subprocess.TimeoutExpired | None = None
        res: subprocess.CompletedProcess[str] | None = None
        for attempt in range(retries + 1):
            try:
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
                if res.returncode != 255 or attempt == retries:
                    break
            except subprocess.TimeoutExpired as exc:
                last_exc = exc
                if attempt == retries or timeout > 60.0:
                    raise
            time.sleep(2.0)
        if res is None:
            assert last_exc is not None
            raise last_exc
        if check and res.returncode != 0:
            raise UTMSupervisorError(
                f"SSH command failed on {self.vm_name} ({self.ip_address}) rc={res.returncode}: "
                f"{res.stderr.strip() or res.stdout.strip()}"
            )
        return res

    def scp_to_guest(
        self,
        local_path: Path,
        remote_path: str,
        *,
        recursive: bool = False,
        timeout: float = 120.0,
        retries: int = 2,
    ) -> None:
        cmd = ["/usr/bin/scp", *build_ssh_base_args(self.private_key)]
        if recursive:
            cmd.append("-r")
        cmd.extend([str(local_path), f"{self.user}@{self.ip_address}:{remote_path}"])
        last_err = ""
        for attempt in range(retries + 1):
            try:
                res = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout, check=False
                )
                if res.returncode == 0:
                    return
                last_err = res.stderr.strip() or res.stdout.strip()
            except subprocess.TimeoutExpired as exc:
                if attempt == retries:
                    raise
                last_err = str(exc)
            time.sleep(2.0)
        raise UTMSupervisorError(f"SCP to {self.vm_name} failed: {last_err}")

    def scp_from_guest(
        self,
        remote_path: str,
        local_path: Path,
        *,
        recursive: bool = False,
        timeout: float = 120.0,
        retries: int = 2,
    ) -> None:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = ["/usr/bin/scp", *build_ssh_base_args(self.private_key)]
        if recursive:
            cmd.append("-r")
        cmd.extend([f"{self.user}@{self.ip_address}:{remote_path}", str(local_path)])
        last_err = ""
        for attempt in range(retries + 1):
            try:
                res = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout, check=False
                )
                if res.returncode == 0:
                    return
                last_err = res.stderr.strip() or res.stdout.strip()
            except subprocess.TimeoutExpired as exc:
                if attempt == retries:
                    raise
                last_err = str(exc)
            time.sleep(2.0)
        raise UTMSupervisorError(f"SCP from {self.vm_name} failed: {last_err}")

class DualSlotUTMSupervisor:
    """Manages disposable UTM VM clones across 1 or 2 concurrent Apple Silicon VM slots."""

    def __init__(
        self,
        *,
        state_dir: Path,
        utm_documents_dir: Path = UTM_DOCUMENTS_DIR,
        host_proxy_port: int | None = 7877,
        guest_proxy_port: int = 17877,
        vm_cpus: int = 4,
        vm_memory_mb: int = 8192,
    ) -> None:
        self.state_dir = state_dir.expanduser().resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.utm_documents_dir = utm_documents_dir.expanduser().resolve()
        self.clone_lock_path = self.state_dir / "utm-clone.lock"
        self.private_key, self.public_key = ensure_ssh_keypair(self.state_dir / "ssh")
        self.host_proxy_port = host_proxy_port
        self.guest_proxy_port = guest_proxy_port
        self.vm_cpus = vm_cpus
        self.vm_memory_mb = vm_memory_mb

    def wait_for_ssh(self, ip: str, *, timeout_seconds: float = 120.0) -> None:
        deadline = time.monotonic() + timeout_seconds
        last_err = ""
        while time.monotonic() < deadline:
            res = subprocess.run(
                [
                    "/usr/bin/ssh",
                    *build_ssh_base_args(self.private_key),
                    f"admin@{ip}",
                    "echo SSH_READY",
                ],
                capture_output=True,
                text=True,
                timeout=12,
                check=False,
            )
            if res.returncode == 0 and "SSH_READY" in res.stdout:
                return
            last_err = res.stderr.strip() or res.stdout.strip()
            time.sleep(2.0)
        raise UTMSupervisorError(f"SSH key auth did not become ready at {ip}: {last_err}")

    def wait_for_guest_http_server(
        self, ip: str, *, port: int = 5000, timeout_seconds: float = 90.0
    ) -> None:
        import requests

        deadline = time.monotonic() + timeout_seconds
        url = f"http://{ip}:{port}/platform"
        while time.monotonic() < deadline:
            try:
                resp = requests.get(url, timeout=3.0)
                if resp.status_code == 200:
                    return
            except Exception:
                pass
            time.sleep(2.0)
        raise UTMSupervisorError(
            f"Guest MacArena Flask server at {url} did not become ready within {timeout_seconds}s"
        )

    def _start_reverse_proxy_tunnel_if_available(
        self, handle: ClonedVMHandle
    ) -> None:
        if self.host_proxy_port is None:
            return
        if not is_tcp_port_open("127.0.0.1", self.host_proxy_port):
            return
        cmd = [
            "/usr/bin/ssh",
            *build_ssh_base_args(self.private_key),
            "-N",
            "-o",
            "ExitOnForwardFailure=yes",
            "-R",
            f"127.0.0.1:{self.guest_proxy_port}:127.0.0.1:{self.host_proxy_port}",
            f"{handle.user}@{handle.ip_address}",
        ]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.8)
        if proc.poll() is None:
            handle.proxy_tunnel_proc = proc
            handle.guest_proxy_url = f"http://127.0.0.1:{self.guest_proxy_port}"
        else:
            with contextlib.suppress(Exception):
                proc.terminate()

    def _start_host_port_forwards(self, handle: ClonedVMHandle) -> None:
        """Forward guest :5000, :9222, :8080 to host 127.0.0.1 ephemeral ports.

        Non-Apple binaries (e.g. ~/.local/share/uv/python) hit macOS 15+/26 Local Network
        Privacy EHOSTUNREACH on 192.168.64.0/24 while /usr/bin/ssh connects cleanly.
        """
        srv_port = pick_ephemeral_local_port()
        chr_port = pick_ephemeral_local_port()
        vlc_port = pick_ephemeral_local_port()
        cmd = [
            "/usr/bin/ssh",
            *build_ssh_base_args(self.private_key),
            "-N",
            "-o",
            "ExitOnForwardFailure=yes",
            "-L",
            f"127.0.0.1:{srv_port}:127.0.0.1:5000",
            "-L",
            f"127.0.0.1:{chr_port}:127.0.0.1:9222",
            "-L",
            f"127.0.0.1:{vlc_port}:127.0.0.1:8080",
            f"{handle.user}@{handle.ip_address}",
        ]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.8)
        if proc.poll() is not None:
            err = (proc.stderr.read() if proc.stderr else "").strip()
            raise UTMSupervisorError(
                f"Failed starting SSH -L forwards to {handle.vm_name} ({handle.ip_address}): {err}"
            )
        handle.host_forward_proc = proc
        handle.host_server_port = srv_port
        handle.host_chromium_port = chr_port
        handle.host_vlc_port = vlc_port

    def verify_guest_aqua_tcc_readiness(
        self,
        handle: ClonedVMHandle,
        *,
        timeout_seconds: float = 45.0,
    ) -> dict[str, Any]:
        """Hard readiness gate verifying `:5000` runs in Aqua GUI domain with active TCC permissions.

        1. Opens a real Finder window (`~/Documents`) inside the guest Aqua session.
        2. Captures a baseline wallpaper-only screenshot (`Finder` windows minimized/closed or hidden)
           vs an open-window screenshot via `:5000/screenshot`, proving `kTCCServiceScreenCapture`
           renders actual application window chrome (non-wallpaper pixel delta & high-brightness region).
        3. Calls `:5000/run_bash_script` with `System Events` -> `name of window 1 of (first application
           process whose frontmost is true)` and asserts `returncode == 0` with a non-empty window title,
           proving `kTCCServiceAccessibility` + `kTCCServiceAppleEvents` are active for `:5000`.
        """
        import io
        import requests
        from PIL import Image

        base_url = f"http://127.0.0.1:{handle.host_server_port}"
        probe_script = (
            "set -e\n"
            "osascript -e 'tell application \"Finder\"\n"
            "  activate\n"
            "  if (count of Finder windows) is 0 then\n"
            "    make new Finder window to (path to documents folder)\n"
            "  else\n"
            "    set target of Finder window 1 to (path to documents folder)\n"
            "    set index of Finder window 1 to 1\n"
            "  end if\n"
            "  set bounds of Finder window 1 to {180, 120, 1260, 820}\n"
            "end tell'\n"
            "sleep 0.6\n"
            "osascript -e 'tell application \"System Events\" to get name of window 1 of (first application process whose frontmost is true)'\n"
        )
        cleanup_script = (
            "osascript -e 'tell application \"Finder\" to close every Finder window' >/dev/null 2>&1 || true"
        )
        deadline = time.monotonic() + timeout_seconds
        last_diag = ""
        try:
            # Capture baseline desktop before opening the probe Finder window (close existing Finder windows first)
            requests.post(
                f"{base_url}/run_bash_script",
                json={"script": cleanup_script, "timeout": 15},
                timeout=20.0,
            )
            time.sleep(0.3)
            baseline_png = requests.get(f"{base_url}/screenshot", timeout=15.0).content
            first_attempt = True
            while first_attempt or time.monotonic() < deadline:
                first_attempt = False
                resp = requests.post(
                    f"{base_url}/run_bash_script",
                    json={"script": probe_script, "timeout": 20},
                    timeout=25.0,
                )
                payload = resp.json() if resp.status_code == 200 else {"returncode": resp.status_code, "output": resp.text}
                rc = payload.get("returncode")
                win_title = str(payload.get("output") or "").strip().splitlines()[-1].strip() if payload.get("output") else ""
                if rc == 0 and win_title and "execution error" not in win_title.lower():
                    shot_resp = requests.get(f"{base_url}/screenshot", timeout=15.0)
                    if shot_resp.status_code == 200 and shot_resp.content:
                        img_open = Image.open(io.BytesIO(shot_resp.content)).convert("RGB")
                        w, h = img_open.size
                        box = (
                            int(min(w - 1, max(0, w * 0.18))),
                            int(min(h - 1, max(0, h * 0.18))),
                            int(min(w, max(1, w * 0.68))),
                            int(min(h, max(1, h * 0.68))),
                        )
                        crop_open = img_open.crop(box).resize((64, 64))
                        raw_open = crop_open.tobytes()
                        mean_luma = sum(raw_open) / max(1, len(raw_open))
                        diff_from_baseline = 0.0
                        if baseline_png:
                            img_base = Image.open(io.BytesIO(baseline_png)).convert("RGB")
                            if img_base.size == img_open.size:
                                raw_base = img_base.crop(box).resize((64, 64)).tobytes()
                                diff_from_baseline = sum(
                                    abs(a - b) for a, b in zip(raw_open, raw_base)
                                ) / max(1, len(raw_open))
                        # Wallpaper-only forest screen has mean center luma ~56.0 and 0.0 diff from baseline!
                        if diff_from_baseline >= 6.0 or mean_luma >= 95.0 or mean_luma <= 42.0:
                            return {
                                "windowTitle": win_title,
                                "returncode": rc,
                                "screenshotSize": [w, h],
                                "centerMeanLuma": round(mean_luma, 2),
                                "baselineMeanAbsDiff": round(diff_from_baseline, 2),
                            }
                        last_diag = (
                            f"ScreenCapture TCC missing (wallpaper-only screenshot: "
                            f"mean_luma={mean_luma:.2f}, diff_from_baseline={diff_from_baseline:.2f})"
                        )
                    else:
                        last_diag = f"/screenshot HTTP {shot_resp.status_code}"
                else:
                    last_diag = f"Accessibility window-1 probe failed: rc={rc} out={payload.get('output')!r}"
                if time.monotonic() >= deadline:
                    break
                time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))
        finally:
            with contextlib.suppress(Exception):
                requests.post(
                    f"{base_url}/run_bash_script",
                    json={"script": cleanup_script, "timeout": 15},
                    timeout=15.0,
                )
        raise UTMSupervisorError(
            f"Guest `:5000` failed hard Aqua TCC readiness probe on {handle.vm_name} ({handle.ip_address}): {last_diag}"
        )

    def start_guest_services(
        self,
        handle: ClonedVMHandle,
        *,
        verify_tcc: bool = True,
    ) -> dict[str, Any] | None:
        """Ensure `:5000` runs strictly via Aqua LaunchAgent (`gui/<uid>`) and passes hard TCC gate.

        NEVER falls back to SSH `nohup python3 main.py &` because `sshd-keygen-wrapper` lacks
        Aqua GUI session context, `kTCCServiceAccessibility`, and `kTCCServiceScreenCapture`.
        """
        startup_script = (
            "set -e; "
            f"PLIST=\"$HOME/{AQUA_LAUNCHAGENT_REL_PATH}\"; "
            "if [ ! -f \"$PLIST\" ]; then "
            "  echo 'MISSING_AQUA_LAUNCHAGENT_PLIST' >&2; "
            "  exit 42; "
            "fi; "
            "UID_NUM=$(id -u); "
            "for _ in $(seq 1 20); do "
            "  if launchctl print \"gui/$UID_NUM\" >/dev/null 2>&1; then break; fi; "
            "  sleep 1; "
            "done; "
            "launchctl print \"gui/$UID_NUM\" >/dev/null 2>&1 || { echo 'AQUA_GUI_SESSION_NOT_LOGGED_IN' >&2; exit 43; }; "
            "if ! lsof -nP -iTCP:5000 -sTCP:LISTEN >/dev/null 2>&1; then "
            f"  launchctl bootstrap \"gui/$UID_NUM\" \"$PLIST\" >/dev/null 2>&1 || "
            f"  launchctl kickstart -k \"gui/$UID_NUM/{AQUA_LAUNCHAGENT_LABEL}\" >/dev/null 2>&1 || true; "
            "fi; "
            "for _ in $(seq 1 20); do "
            "  if lsof -nP -iTCP:5000 -sTCP:LISTEN >/dev/null 2>&1; then break; fi; "
            "  sleep 1; "
            "done; "
            "lsof -nP -iTCP:5000 -sTCP:LISTEN >/dev/null 2>&1 || { echo 'AQUA_LAUNCHAGENT_PORT_5000_NOT_LISTENING' >&2; exit 44; }; "
            f"launchctl print \"gui/$UID_NUM/{AQUA_LAUNCHAGENT_LABEL}\" >/dev/null 2>&1 || "
            "{ echo 'PORT_5000_NOT_OWNED_BY_AQUA_LAUNCHAGENT' >&2; exit 45; }"
        )
        handle.ssh_run(startup_script, timeout=60.0)
        if handle.host_forward_proc is None:
            self._start_host_port_forwards(handle)
        self.wait_for_guest_http_server("127.0.0.1", port=handle.host_server_port, timeout_seconds=60.0)
        if verify_tcc:
            return self.verify_guest_aqua_tcc_readiness(handle)
        return None

    def acquire_disposable_vm(
        self,
        *,
        slot_id: int,
        base_vm_name: str,
        task_id: str,
    ) -> ClonedVMHandle:
        """Clone Golden Base VM into an isolated slot VM, patch MAC + ECID, boot, and connect."""
        short_id = hashlib.sha1(f"{task_id}-{uuid.uuid4().hex}".encode()).hexdigest()[:10]
        vm_name = f"fsq-slot{slot_id}-{short_id}"
        mac_address = generate_slot_mac(slot_id)

        with FileLock(str(self.clone_lock_path), timeout=300):
            base_bundle = self.utm_documents_dir / f"{base_vm_name}.utm"
            if not base_bundle.is_dir():
                raise UTMSupervisorError(
                    f"Golden Base VM bundle not found in vm_golden: {base_bundle}"
                )
            cloned_bundle = self.utm_documents_dir / f"{vm_name}.utm"
            if cloned_bundle.exists():
                import shutil

                shutil.rmtree(cloned_bundle, ignore_errors=True)
            cp_res = subprocess.run(
                ["/bin/cp", "-cR", str(base_bundle), str(cloned_bundle)],
                capture_output=True,
                text=True,
                check=False,
            )
            if cp_res.returncode != 0:
                import shutil

                shutil.copytree(base_bundle, cloned_bundle)
            cloned_plist = cloned_bundle / "config.plist"
            patch_cloned_vm_config_plist(
                cloned_plist,
                vm_name=vm_name,
                mac_address=mac_address,
                slot_id=slot_id,
                cpu_count=self.vm_cpus,
                memory_mb=self.vm_memory_mb,
            )
            # Register cloned bundle with UTM before starting (stays outside TCC sandboxed container!)
            subprocess.run(
                ["/usr/bin/open", "-g", "-a", "/Applications/UTM.app", str(cloned_bundle)],
                capture_output=True,
                text=True,
                timeout=15.0,
                check=False,
            )
            for _ in range(20):
                ls_out = run_utmctl(["list"], check=False, hide=True, timeout=10.0).stdout
                if vm_name in ls_out:
                    break
                time.sleep(0.5)
            run_utmctl(["start", vm_name], hide=True, timeout=60.0)
            time.sleep(2.0)
        handle: ClonedVMHandle | None = None
        try:
            ip = resolve_guest_ip(vm_name, mac_address, timeout_seconds=120.0)
            self.wait_for_ssh(ip, timeout_seconds=120.0)
            handle = ClonedVMHandle(
                slot_id=slot_id,
                base_vm_name=base_vm_name,
                vm_name=vm_name,
                mac_address=mac_address,
                ip_address=ip,
                private_key=self.private_key,
            )
            self._start_reverse_proxy_tunnel_if_available(handle)
            handle.tcc_readiness_receipt = self.start_guest_services(handle)
            return handle
        except BaseException:
            if handle is not None:
                self.release_disposable_vm(handle)
            else:
                self.destroy_vm_by_name(vm_name)
            raise

    def release_disposable_vm(self, handle: ClonedVMHandle) -> dict[str, Any]:
        for proc_attr in ("proxy_tunnel_proc", "host_forward_proc"):
            proc = getattr(handle, proc_attr, None)
            if proc is not None:
                with contextlib.suppress(Exception):
                    proc.terminate()
                    proc.wait(timeout=5)
                setattr(handle, proc_attr, None)
        return self.destroy_vm_by_name(handle.vm_name)
    def destroy_vm_by_name(self, vm_name: str) -> dict[str, Any]:
        stopped = False
        deleted = False
        with contextlib.suppress(Exception):
            run_utmctl(["stop", vm_name], check=False, hide=True, timeout=30.0)
            for _ in range(20):
                st = run_utmctl(["status", vm_name], check=False, hide=True, timeout=10.0)
                if "stopped" in st.stdout.lower():
                    stopped = True
                    break
                time.sleep(1.5)
        with FileLock(str(self.clone_lock_path), timeout=120):
            res = run_utmctl(["delete", vm_name], check=False, hide=True, timeout=60.0)
            deleted = res.returncode == 0
            leftover = self.utm_documents_dir / f"{vm_name}.utm"
            if leftover.exists():
                import shutil

                shutil.rmtree(leftover, ignore_errors=True)
                deleted = not leftover.exists()
        return {"vmName": vm_name, "stopped": stopped, "deleted": deleted}
