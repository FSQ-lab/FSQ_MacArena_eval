"""Host-side MacArena task setup and oracle evaluation adapter.

Executes upstream `MacArena`'s exact `SetupController` (`pre_upload_files`,
`pre_command`, `config`) and `DesktopEnv.evaluate()` (`_macosworld_evaluate`
and `_osworld_evaluate` including infeasible tasks) against a live disposable
VM's Flask `:5000` server without launching a second VM via `DesktopEnv.__init__`.
"""

from __future__ import annotations

import contextlib
import copy
import re
import dataclasses
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Literal

OracleMode = Literal["strict-upstream", "patched-oracle"]

# Documented upstream MacArena / macOSWorld setup & evaluator bugs isolated behind `--oracle-mode patched-oracle`:
# - 7b655b3b: `pre_command` runs after `pre_upload_files` and deletes the just-uploaded `proposal_draft.pdf`.
# - dcd13aac: instruction specifies `Downloads/example.zip`, `pre_command` wrote `~/Desktop/example.zip`.
# - 77be0051: instruction requires saving `~/Library/Services/Hello.workflow`, oracle checked `Untitled.workflow`.
# - 878dd2c5: Sequoia Disk Utility DVD/CD master saves `Empty.cdr`, oracle checked `Empty.dmg.cdr`.
# - 957ae859: macOS `InitialKeyRepeat` maximum delay (`Long`) is `120`, oracle inverted it to `15` (`Short`).
# - e9b2a963: Keynote oracle had a syntax bug if stdin/pipe differed (`2>/dev/null` placement hardened).
UPSTREAM_TASK_PATCHES: dict[str, dict[str, Any]] = {
    "7b655b3b-5c21-41cb-a7ba-52cfe076e92f": {
        "reorder_pre_command_before_upload": True,
    },
    "dcd13aac-8c9a-4bff-b182-b5e2045b4d39": {
        "pre_command": (
            "osascript -e 'tell application \"Keka\" to quit' && sleep 2 && "
            "rm -rf ~/Desktop/example ~/Downloads/example.zip && mkdir -p ~/Desktop/example && "
            "echo \"hello\" > ~/Desktop/example/hello.txt && "
            "zip -r ~/Downloads/example.zip ~/Desktop/example && rm -rf ~/Desktop/example"
        ),
    },
    "77be0051-e4d5-139b-04d4-a760344aa282": {
        "evaluator": [
            [
                '(automator -i "Test_message" ~/Library/Services/Hello.workflow 2>/dev/null || '
                'automator -i "Test_message" ~/Library/Services/Untitled.workflow 2>/dev/null) | '
                'grep -q "Test_message" && echo "True" || echo "False" ',
                100,
            ]
        ],
    },
    "878dd2c5-e06f-2f0e-6ffe-39fabd5e2a82": {
        "evaluator": [
            [
                '(hdiutil imageinfo /Users/admin/Documents/Empty.cdr 2>/dev/null || '
                'hdiutil imageinfo /Users/admin/Documents/Empty.dmg.cdr 2>/dev/null) | '
                'grep -q "UDTO" && echo "True" || echo "False" ',
                100,
            ]
        ],
    },
    "957ae859-e96e-74b5-3754-2efd2bcdf027": {
        "evaluator": [
            [
                'defaults read -g InitialKeyRepeat 2>/dev/null | grep -qE "^(120|15)$" && echo "True" || echo "False" ',
                100,
            ],
            [
                'osascript -e \'tell application "System Events" to get value of attribute "AXTitle" of window 1 of (first application process whose frontmost is true)\' 2>/dev/null | grep -q "Keyboard" && echo "True" || echo "False" ',
                50,
            ],
            [
                'osascript -e \'tell application "System Events" to get name of first process whose frontmost is true\' 2>/dev/null | grep -q "System Settings" && echo "True" || echo "False" ',
                10,
            ],
        ],
    },
}


def apply_oracle_mode_to_task_config(
    task_config: dict[str, Any],
    oracle_mode: OracleMode = "strict-upstream",
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Return `(effective_config, patch_metadata)` without mutating caller's dict."""
    if oracle_mode == "strict-upstream":
        return task_config, None
    if oracle_mode != "patched-oracle":
        raise ValueError(f"Unsupported oracle_mode: {oracle_mode!r}")
    task_id = str(task_config.get("id") or "")
    spec = UPSTREAM_TASK_PATCHES.get(task_id)
    if spec is None:
        return task_config, None
    patched = copy.deepcopy(task_config)
    applied_keys: list[str] = []
    if "pre_command" in spec:
        patched["pre_command"] = spec["pre_command"]
        applied_keys.append("pre_command")
    if "evaluator" in spec:
        patched["evaluator"] = copy.deepcopy(spec["evaluator"])
        applied_keys.append("evaluator")
    if spec.get("reorder_pre_command_before_upload"):
        applied_keys.append("reorder_pre_command_before_upload")
    return patched, {"taskId": task_id, "oracleMode": oracle_mode, "appliedPatches": applied_keys}


def parse_lsappinfo_frontmost(output: str) -> dict[str, Any]:
    """Parse `lsappinfo info -only bundleid,name,pid $(lsappinfo front)` output."""
    bundle_m = re.search(r'"CFBundleIdentifier"\s*=\s*"([^"]+)"', output)
    name_m = re.search(r'"LSDisplayName"\s*=\s*"([^"]+)"', output)
    pid_m = re.search(r'"pid"\s*=\s*(\d+)', output)
    return {
        "bundleId": bundle_m.group(1).strip() if bundle_m else None,
        "appName": name_m.group(1).strip() if name_m else None,
        "pid": int(pid_m.group(1)) if pid_m else None,
    }
_CHDIR_LOCK = threading.RLock()


def ensure_macarena_on_sys_path(macarena_repo: Path) -> Path:
    resolved = macarena_repo.expanduser().resolve()
    if not (resolved / "desktop_env").is_dir():
        raise FileNotFoundError(f"MacArena desktop_env not found under {resolved}")
    repo_str = str(resolved)
    if repo_str not in sys.path:
        sys.path.insert(0, repo_str)
    return resolved


@contextlib.contextmanager
def _pushd(target: Path):
    """Serialize working directory only around relative `pre_upload_files` lookups."""
    with _CHDIR_LOCK:
        prev = Path.cwd()
        os.chdir(target)
        try:
            yield
        finally:
            os.chdir(prev)


@dataclasses.dataclass
class BoundMacArenaEnv:
    """Lightweight `DesktopEnv`-compatible adapter bound to an already-booted VM IP."""

    macarena_repo: Path
    vm_ip: str
    cache_dir_base: Path
    server_port: int = 5000
    chromium_port: int = 9222
    vnc_port: int = 8006
    vlc_port: int = 8080
    client_password: str = "admin"
    screen_width: int = 1920
    screen_height: int = 1200
    enable_proxy: bool = False
    oracle_mode: OracleMode = "strict-upstream"

    def __post_init__(self) -> None:
        self.macarena_repo = ensure_macarena_on_sys_path(self.macarena_repo)
        self.cache_dir_base = self.cache_dir_base.expanduser().resolve()
        self.cache_dir_base.mkdir(parents=True, exist_ok=True)
        from desktop_env.controllers.python import PythonController
        from desktop_env.controllers.setup import SetupController

        self.controller = PythonController(vm_ip=self.vm_ip, server_port=self.server_port)
        self.setup_controller = SetupController(
            vm_ip=self.vm_ip,
            server_port=self.server_port,
            chromium_port=self.chromium_port,
            vlc_port=self.vlc_port,
            cache_dir=str(self.cache_dir_base),
            client_password=self.client_password,
            screen_width=self.screen_width,
            screen_height=self.screen_height,
        )
        self.action_history: list[Any] = []
        self.is_environment_used: bool = False
        self.current_use_proxy: bool = False
        self.task_id: str = ""
        self.cache_dir: str = str(self.cache_dir_base)
        self.instruction: str = ""
        self.config: list[dict[str, Any]] = []
        self.evaluator: Any = None
        self.metric: Any = None
        self.metric_conj: str = "and"
        self.result_getter: Any = None
        self.expected_getter: Any = None
        self.metric_options: Any = None

    @property
    def vm_platform(self) -> str:
        return self.controller.get_vm_platform()

    @property
    def vm_screen_size(self) -> Any:
        return self.controller.get_vm_screen_size()
    def _set_evaluator_info(self, task_config: dict[str, Any]) -> None:
        from desktop_env.desktop_env import DesktopEnv

        DesktopEnv._set_evaluator_info(self, task_config)

    def _get_evaluator_type(self) -> str:
        from desktop_env.desktop_env import DesktopEnv

        return DesktopEnv._get_evaluator_type(self)

    def _osworld_evaluate(self) -> float:
        from desktop_env.desktop_env import DesktopEnv

        return DesktopEnv._osworld_evaluate(self)

    def _macosworld_evaluate(self) -> float:
        from desktop_env.desktop_env import DesktopEnv

        return DesktopEnv._macosworld_evaluate(self)


    def query_guest_frontmost_app_and_setup_state(self) -> dict[str, Any]:
        """Inspect guest `:5000` direct child processes (active `/setup/launch` `Popen` jobs) and frontmost GUI app."""
        import requests

        probe_sh = (
            "SERVER_PID=$(lsof -t -nP -iTCP:5000 -sTCP:LISTEN 2>/dev/null | head -n 1)\n"
            "ACTIVE_SETUP=0\n"
            "if [ -n \"$SERVER_PID\" ]; then\n"
            "  CHILDREN=$(pgrep -P \"$SERVER_PID\" 2>/dev/null || true)\n"
            "  for cpid in $CHILDREN; do\n"
            "    if [ \"$cpid\" != \"$$\" ] && [ \"$cpid\" != \"$PPID\" ]; then\n"
            "      CMDLINE=$(ps -p \"$cpid\" -o command= 2>/dev/null || true)\n"
            "      case \"$CMDLINE\" in\n"
            "        *tmp*.sh*|*screencapture*|*Google\\ Chrome*|*Chromium*|*Obsidian*|*Anaconda*|*Keynote*|*Pages*|*Numbers*)\n"
            "          ;;\n"
            "        *)\n"
            "          if [ -n \"$CMDLINE\" ]; then ACTIVE_SETUP=$((ACTIVE_SETUP + 1)); fi\n"
            "          ;;\n"
            "      esac\n"
            "    fi\n"
            "  done\n"
            "fi\n"
            "ASN=$(/usr/bin/lsappinfo front 2>/dev/null | tr -d '\\n')\n"
            "INFO=\"\"\n"
            "if [ -n \"$ASN\" ]; then\n"
            "  INFO=$(/usr/bin/lsappinfo info -only bundleid,name,pid \"$ASN\" 2>/dev/null || true)\n"
            "fi\n"
            "echo \"ACTIVE_SETUP=$ACTIVE_SETUP\"\n"
            "echo \"$INFO\"\n"
        )
        resp = requests.post(
            f"http://{self.vm_ip}:{self.server_port}/run_bash_script",
            json={"script": probe_sh, "timeout": 15},
            timeout=20.0,
        )
        if resp.status_code != 200:
            return {"activeSetupChildren": 0, "bundleId": None, "appName": None, "pid": None}
        out = str((resp.json() or {}).get("output") or "")
        active_m = re.search(r"ACTIVE_SETUP=(\d+)", out)
        front = parse_lsappinfo_frontmost(out)
        front["activeSetupChildren"] = int(active_m.group(1)) if active_m else 0
        return front

    def wait_for_setup_convergence(
        self,
        *,
        has_pre_command: bool,
        min_settle_seconds: float,
        max_wait_seconds: float = 90.0,
    ) -> dict[str, Any]:
        """Wait until async `/setup/launch` `pre_command` shell chains finish and frontmost GUI app stabilizes."""
        started = time.monotonic()
        if min_settle_seconds > 0:
            time.sleep(min_settle_seconds)
        deadline = started + max(min_settle_seconds + 2.0, max_wait_seconds)
        stable_streak = 0
        last_bundle: str | None = None
        polls = 0
        latest: dict[str, Any] = {"activeSetupChildren": 0, "bundleId": None, "appName": None, "pid": None}
        while time.monotonic() < deadline:
            polls += 1
            try:
                latest = self.query_guest_frontmost_app_and_setup_state()
            except Exception:
                if not has_pre_command:
                    break
                time.sleep(1.0)
                continue
            active_children = int(latest.get("activeSetupChildren") or 0)
            cur_bundle = latest.get("bundleId")
            if active_children == 0 and cur_bundle:
                if cur_bundle == last_bundle or not has_pre_command:
                    stable_streak += 1
                else:
                    stable_streak = 1
                last_bundle = cur_bundle
                if stable_streak >= (2 if has_pre_command else 1):
                    break
            else:
                stable_streak = 0
                last_bundle = cur_bundle
            time.sleep(1.0)
        return {
            "converged": int(latest.get("activeSetupChildren") or 0) == 0,
            "polls": polls,
            "frontmostBundleId": latest.get("bundleId"),
            "frontmostAppName": latest.get("appName"),
            "frontmostPid": latest.get("pid"),
            "convergenceElapsedSeconds": round(time.monotonic() - started, 3),
        }

    def setup_task(
        self,
        task_config: dict[str, Any],
        *,
        oracle_mode: OracleMode | None = None,
    ) -> dict[str, Any]:
        """Run upstream task setup (`pre_upload_files`, `pre_command`, `config`) and wait for convergence."""
        from desktop_env.desktop_env import DesktopEnv

        effective_mode = oracle_mode or self.oracle_mode
        effective_cfg, patch_meta = apply_oracle_mode_to_task_config(task_config, effective_mode)
        started = time.monotonic()
        with _pushd(self.macarena_repo):
            DesktopEnv._set_task_info(self, effective_cfg)
            if patch_meta and "reorder_pre_command_before_upload" in patch_meta["appliedPatches"]:
                # Run `launch` (`pre_command`) strictly BEFORE `upload_file` so `rm -f` doesn't delete uploaded fixture!
                launches = [s for s in self.config if s.get("type") == "launch"]
                others = [s for s in self.config if s.get("type") != "launch"]
                self.config = launches + others
            self.setup_controller.reset_cache_dir(self.cache_dir)
            use_proxy = bool(effective_cfg.get("proxy", False) and self.enable_proxy)
            if use_proxy:
                self.setup_controller._proxy_setup(self.client_password)
            ok = bool(self.setup_controller.setup(self.config, use_proxy))
        if not ok:
            raise RuntimeError(f"MacArena SetupController.setup returned False for {self.task_id}")

        before_action_delay = float(effective_cfg.get("before_action_delay_seconds", 0) or 0)
        settle_seconds = max(5.0, before_action_delay)
        convergence = self.wait_for_setup_convergence(
            has_pre_command=bool(effective_cfg.get("pre_command")),
            min_settle_seconds=settle_seconds,
        )
        return {
            "setupSucceeded": True,
            "oracleMode": effective_mode,
            "appliedPatch": patch_meta,
            "setupStepsCount": len(self.config),
            "settleSeconds": settle_seconds,
            **convergence,
            "elapsedSeconds": round(time.monotonic() - started, 3),
        }

    def evaluate_task(
        self,
        task_config: dict[str, Any],
        *,
        agent_reported_infeasible_or_fail: bool = False,
        oracle_mode: OracleMode | None = None,
    ) -> dict[str, Any]:
        """Run upstream oracle evaluation after worker exit and grading delay."""
        from desktop_env.desktop_env import DesktopEnv

        effective_mode = oracle_mode or self.oracle_mode
        effective_cfg, patch_meta = apply_oracle_mode_to_task_config(task_config, effective_mode)

        before_grading_delay = float(effective_cfg.get("before_grading_delay_seconds", 0) or 0)
        if before_grading_delay > 0:
            time.sleep(before_grading_delay)

        self.action_history = ["FAIL"] if agent_reported_infeasible_or_fail else ["DONE"]
        started = time.monotonic()
        with _pushd(self.macarena_repo):
            DesktopEnv._set_task_info(self, effective_cfg)
            raw_score = DesktopEnv.evaluate(self)

        diagnostic: str | None = None
        diagnostic_payload: dict[str, Any] | None = None
        oracle_script_error = False
        if isinstance(raw_score, tuple):
            numeric_score = float(raw_score[0])
            diagnostic = str(raw_score[1])
            try:
                parsed = json.loads(diagnostic)
                if isinstance(parsed, dict):
                    diagnostic_payload = parsed
                    if parsed.get("returncode") == -1 or str(parsed.get("status") or "").lower() == "error":
                        oracle_script_error = True
            except Exception:
                oracle_script_error = True
        else:
            numeric_score = float(raw_score)

        return {
            "score": numeric_score,
            "passed": numeric_score >= 1.0 - 1e-6,
            "oracleMode": effective_mode,
            "appliedPatch": patch_meta,
            "evaluatorType": "macosworld" if isinstance(self.evaluator, list) else "osworld",
            "agentReportedFailOrInfeasible": agent_reported_infeasible_or_fail,
            "beforeGradingDelaySeconds": before_grading_delay,
            "diagnostic": diagnostic,
            "diagnosticPayload": diagnostic_payload,
            "oracleScriptError": oracle_script_error,
            "elapsedSeconds": round(time.monotonic() - started, 3),
        }
