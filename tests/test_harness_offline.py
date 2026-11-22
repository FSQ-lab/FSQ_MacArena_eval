"""Offline unit tests for freeze manifest, task discovery, dispatch budget, dual-slot plist patching, worker, and evaluator."""

from __future__ import annotations

import dataclasses
import json
import plistlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from fsq_macarena_eval.evaluator import BoundMacArenaEnv
from fsq_macarena_eval.fsq_native import (
    BudgetedMacOSHarness,
    NativeActionBudgetExceeded,
    NativeDeadlineExceeded,
    NativeMacOSDispatchBudget,
)
from fsq_macarena_eval.fsq_worker import (
    NativeMacOSBindings,
    execute_worker,
    select_main_answer,
)
from fsq_macarena_eval.manifest import (
    EXPECTED_SUBSET_COUNTS,
    INITIAL_BUNDLE_ID,
    discover_tasks,
    select_smoke_6_tasks,
    verify_frozen_wheels,
)
from fsq_macarena_eval.runner import classify_episode_outcome
from fsq_macarena_eval.utm_supervisor import (
    SLOT_ECIDS,
    generate_slot_mac,
    lookup_dhcp_ip_for_mac,
    patch_cloned_vm_config_plist,
)

MACARENA_REPO = Path(__file__).resolve().parent.parent / "MacArena"


def test_verify_frozen_wheels_exact_sha256() -> None:
    receipt = verify_frozen_wheels()
    assert receipt["provider"] == "github_copilot"
    assert receipt["model"] == "gpt-6.1-sol"
    assert receipt["initialBundleId"] == "auto"
    wheels = {w["packageName"]: w for w in receipt["wheels"]}
    assert wheels["appium-connect-agent"]["version"] == "0.1.2"
    assert wheels["appium-connect-agent"]["editable"] is False
    assert wheels["fsq-agent"]["version"] == "0.3.8"
    assert wheels["fsq-agent"]["editable"] is False


def test_discover_all_421_tasks_and_smoke_6() -> None:
    records = discover_tasks(MACARENA_REPO)
    assert len(records) == 421
    by_sub: dict[str, int] = {}
    for rec in records:
        by_sub[rec.subset] = by_sub.get(rec.subset, 0) + 1
    assert by_sub == EXPECTED_SUBSET_COUNTS

    smoke = select_smoke_6_tasks(MACARENA_REPO)
    assert len(smoke) == 6
    assert [t.subset for t in smoke] == [
        "macarena",
        "macarena",
        "macosworld",
        "macosworld",
        "osworld",
        "osworld",
    ]
    assert len({t.task_id for t in smoke}) == 6


def test_native_macos_dispatch_budget_and_launch_app_telemetry(tmp_path: Path) -> None:
    now = 100.0
    journal = tmp_path / "audit.jsonl"
    budget = NativeMacOSDispatchBudget(2, 200.0, clock=lambda: now, journal=journal)

    # Read action does not consume write budget
    read_step = SimpleNamespace(action_name="ui_snapshot", kind="observation", step_id="s1", params={})
    budget.dispatch(
        read_step.action_name,
        read_step.kind,
        lambda: SimpleNamespace(status="passed", failure_category=None),
        step_id=read_step.step_id,
        step=read_step,
    )
    assert budget.snapshot()["admitted"] == 0

    # First write: launch_app(new_session=False) fails -> recorded in launchAppCalls
    launch_step = SimpleNamespace(
        action_name="launch_app",
        kind="action",
        step_id="s2",
        params={"bundle_id": "com.apple.Notes", "new_session": False},
    )
    budget.dispatch(
        launch_step.action_name,
        launch_step.kind,
        lambda: SimpleNamespace(status="failed", failure_category="action_error"),
        step_id=launch_step.step_id,
        step=launch_step,
    )

    # Second write: click_on succeeds
    click_step = SimpleNamespace(action_name="click_on", kind="action", step_id="s3", params={})
    budget.dispatch(
        click_step.action_name,
        click_step.kind,
        lambda: SimpleNamespace(status="passed", failure_category=None),
        step_id=click_step.step_id,
        step=click_step,
    )

    # Third write denied by action budget
    with pytest.raises(NativeActionBudgetExceeded):
        budget.dispatch(
            "type_text",
            "action",
            lambda: SimpleNamespace(status="passed", failure_category=None),
            step_id="s4",
        )

    # The native wrapper still forwards local color sampling after all writes are spent.
    rgb = SimpleNamespace(status="passed", output={"rgb": [0, 191, 243]})
    harness = BudgetedMacOSHarness(SimpleNamespace(invoke_action=lambda step, ctx: rgb), budget)
    sample = SimpleNamespace(action_name="sampleColor", kind="observation", step_id="sample", params={})
    assert harness.invoke_action(sample, None) is rgb
    sample_events = [e for e in budget.snapshot()["events"] if e.get("capability") == "sample_color"]
    assert [(e["event"], e["countedWrite"]) for e in sample_events] == [
        ("attempted", False),
        ("succeeded", False),
    ]

    snap = budget.snapshot()
    assert snap["admitted"] == 2
    assert snap["succeeded"] == 1
    assert snap["failed"] == 1
    assert snap["denied"] == 1
    assert len(snap["launchAppCalls"]) == 1
    assert snap["launchAppCalls"][0]["bundleId"] == "com.apple.Notes"
    assert snap["launchAppCalls"][0]["newSession"] is False
    assert snap["launchAppCalls"][0]["succeeded"] is False


def test_budgeted_macos_harness_forwards_run_visual_surface() -> None:
    budget = NativeMacOSDispatchBudget(1, 200.0, clock=lambda: 100.0)
    native = SimpleNamespace(
        visual_ai_eligible=True, available_scoped_visual_tools=("inspect_with_ai",)
    )
    wrapper = BudgetedMacOSHarness(native, budget)
    assert wrapper.visual_ai_eligible is True
    assert wrapper.available_scoped_visual_tools == ("inspect_with_ai",)
    legacy = BudgetedMacOSHarness(SimpleNamespace(), budget)
    assert legacy.visual_ai_eligible is not True
    assert not legacy.available_scoped_visual_tools


def test_patch_cloned_vm_config_plist_isolates_dual_slots(tmp_path: Path) -> None:
    base_ident = plistlib.dumps({"ECID": 11111111}, fmt=plistlib.FMT_BINARY)
    sample_plist = {
        "Information": {"Name": "MacArena", "UUID": "OLD-UUID"},
        "Network": [{"MacAddress": "aa:bb:cc:dd:ee:ff", "Mode": "Shared"}],
        "System": {
            "CPUCount": 0,
            "MemorySize": 8192,
            "MacPlatform": {"MachineIdentifier": base_ident},
        },
    }
    p0 = tmp_path / "slot0.plist"
    p1 = tmp_path / "slot1.plist"
    p0.write_bytes(plistlib.dumps(sample_plist))
    p1.write_bytes(plistlib.dumps(sample_plist))

    mac0 = generate_slot_mac(0)
    mac1 = generate_slot_mac(1)
    patch_cloned_vm_config_plist(p0, vm_name="vm-slot0", mac_address=mac0, slot_id=0)
    patch_cloned_vm_config_plist(p1, vm_name="vm-slot1", mac_address=mac1, slot_id=1)

    loaded0 = plistlib.loads(p0.read_bytes())
    loaded1 = plistlib.loads(p1.read_bytes())
    assert loaded0["Network"][0]["MacAddress"] == mac0
    assert loaded1["Network"][0]["MacAddress"] == mac1
    assert mac0 != mac1
    ecid0 = plistlib.loads(loaded0["System"]["MacPlatform"]["MachineIdentifier"])["ECID"]
    ecid1 = plistlib.loads(loaded1["System"]["MacPlatform"]["MachineIdentifier"])["ECID"]
    assert ecid0 == SLOT_ECIDS[0]
    assert ecid1 == SLOT_ECIDS[1]
    assert ecid0 != ecid1


def test_lookup_dhcp_ip_for_mac_normalizes_leading_zeros(tmp_path: Path) -> None:
    leases = tmp_path / "dhcpd_leases"
    leases.write_text(
        "{\n"
        "\tname=macarena\n"
        "\tip_address=192.168.64.18\n"
        "\thw_address=1,2:a0:0:9:c1:5\n"
        "\tlease=0x69200010\n"
        "}\n",
        encoding="utf-8",
    )
    assert lookup_dhcp_ip_for_mac("02:a0:00:09:c1:05", leases_path=leases) == "192.168.64.18"


async def test_execute_worker_with_fake_bindings(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    out_dir = tmp_path / "out"

    def fake_init(req: Any) -> None:
        cfg = Path(req.current_directory) / ".fsq" / "config" / "config.macos.yaml"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text("initialized: true\n", encoding="utf-8")
    class FakeSettings:
        def __init__(self) -> None:
            self.harness = SimpleNamespace(
                platform="macos",
                macos=SimpleNamespace(
                    backend="appium_connect_agent",
                    bundle_id=INITIAL_BUNDLE_ID,
                    page_source_max_depth=12,
                    action_timeout_seconds=10,
                    visual_assertion_policy=None,
                    skip_app_kill=False,
                ),
            )
            self.agent_runtime = SimpleNamespace(
                provider="github_copilot",
                model="gpt-6.1-sol",
                max_turns=100,
                reasoning_effort="mid",
                tracing_enabled=True,
            )
            self.output = SimpleNamespace(runs_dir=tmp_path / "runs")

        def model_copy(self, *, deep: bool = False) -> FakeSettings:
            return self

    class FakeAgent:
        @classmethod
        def from_settings(cls, settings: Any, *, runtime_factory: Any, harness_factory: Any) -> FakeAgent:
            cls.last_harness = harness_factory("run-001")
            return cls()

    class FakeTaskResult:
        def model_dump(self, *, mode: str = "json") -> dict[str, Any]:
            return {
                "task_id": "t-1",
                "status": "passed",
                "steps": [
                    {
                        "action": "agent_runtime.runner",
                        "tool_output": {"status": "passed", "summary": "Created note successfully."},
                    }
                ],
                "verification": {"status": "passed"},
                "report": {"path": str(tmp_path / "report.md")},
            }

    class FakeService:
        def __init__(self, *, agent: Any) -> None:
            self.agent = agent

        async def execute(self, req: Any) -> Any:
            req.cancellation_check()
            step = SimpleNamespace(
                action_name="launch_app",
                kind="action",
                step_id="step-1",
                params={"bundle_id": "com.apple.Notes", "new_session": False},
            )
            FakeAgent.last_harness.invoke_action(step, None)
            FakeAgent.last_harness.close()
            return SimpleNamespace(task_result=FakeTaskResult())

    def fake_harness_factory_builder(settings: Any, budget: NativeMacOSDispatchBudget) -> Any:
        class DummyNative:
            def invoke_action(self, step: Any, ctx: Any) -> Any:
                return SimpleNamespace(status="passed", failure_category=None)

            def close(self) -> None:
                return None

        return lambda run_id: BudgetedMacOSHarness(DummyNative(), budget)

    bindings = NativeMacOSBindings(
        initialize_workspace=fake_init,
        workspace_init_request_type=lambda **kw: SimpleNamespace(**kw),
        load_settings=lambda ws, plat, **kw: FakeSettings(),
        agent_type=FakeAgent,
        runtime_factory=lambda *a, **kw: None,
        execution_service_type=FakeService,
        execution_request_type=lambda **kw: SimpleNamespace(**kw),
        task_type=lambda **kw: SimpleNamespace(**kw),
        harness_factory_builder=fake_harness_factory_builder,
        validate_output=None,
    )

    resp = await execute_worker(
        {
            "schemaVersion": 1,
            "workspace": str(workspace),
            "outputDir": str(out_dir),
            "taskId": "smoke-notes-1",
            "goal": "Create a note titled Hello",
            "bundleId": INITIAL_BUNDLE_ID,
            "maxActions": 10,
            "businessDeadlineMonotonic": 999999999.0,
            "provider": "github_copilot",
            "model": "gpt-6.1-sol",
            "runtimeProfile": {"maxTurns": 50},
        },
        bindings=bindings,
    )
    assert resp["status"] == "completed"
    assert resp["mainAnswer"]["status"] == "present"
    assert resp["actionBudget"]["admitted"] == 1
    assert resp["actionBudget"]["launchAppCalls"][0]["newSession"] is False
    assert resp["cleanup"]["closeReceipts"][-1]["event"] == "close_succeeded"
    assert resp["nativeTarget"]["skipAppKill"] is True

    outcome = classify_episode_outcome({"worker": resp, "oracle": {"score": 1.0, "passed": True}})
    assert outcome == {"owner": "none", "category": "passed"}


def test_bound_macarena_env_loads_all_421_task_configs_without_error(tmp_path: Path) -> None:
    records = discover_tasks(MACARENA_REPO)
    env = BoundMacArenaEnv(
        macarena_repo=MACARENA_REPO,
        vm_ip="127.0.0.1",
        server_port=5000,
        cache_dir_base=tmp_path / "cache",
    )
    from desktop_env.desktop_env import DesktopEnv

    for rec in records:
        DesktopEnv._set_task_info(env, rec.config)
        assert env.task_id == rec.task_id
        assert env._get_evaluator_type() in {"macosworld", "osworld"}


def test_classify_oracle_script_error_vs_task_goal_not_satisfied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # 1. Exact diagnostic payload from returncode == -1 / status == error -> benchmark_evaluator:oracle_script_error
    err_diag = json.dumps(
        {
            "status": "error",
            "output": "",
            "error": "Failed to execute bash script after 3 retries",
            "returncode": -1,
            "command": "osascript -e 'tell application \"Notes\" ...'",
        }
    )
    rec_err = {
        "worker": {"status": "completed", "actionBudget": {"launchAppCalls": []}},
        "oracle": {"score": 0.0, "passed": False, "diagnostic": err_diag},
    }
    assert classify_episode_outcome(rec_err) == {
        "owner": "benchmark_evaluator",
        "category": "oracle_script_error",
    }

    # 2. BoundMacArenaEnv.evaluate_task parses tuple (0, json_diag) and sets oracleScriptError=True
    env = BoundMacArenaEnv(
        macarena_repo=MACARENA_REPO,
        vm_ip="127.0.0.1",
        server_port=5000,
        cache_dir_base=tmp_path / "cache",
    )
    from desktop_env.desktop_env import DesktopEnv

    monkeypatch.setattr(DesktopEnv, "evaluate", lambda self: (0, err_diag))
    oracle_res = env.evaluate_task(
        {
            "id": "t-notes",
            "instruction": "test",
            "evaluator": [["echo False", 100]],
            "before_grading_delay_seconds": 0,
        }
    )
    assert oracle_res["oracleScriptError"] is True
    assert oracle_res["diagnosticPayload"]["returncode"] == -1
    assert classify_episode_outcome({"worker": {"status": "completed"}, "oracle": oracle_res}) == {
        "owner": "benchmark_evaluator",
        "category": "oracle_script_error",
    }

    # 3. Normal 0.0 score without script error stays subject_fsq:task_goal_not_satisfied
    rec_clean_fail = {
        "worker": {"status": "completed", "actionBudget": {"launchAppCalls": []}},
        "oracle": {"score": 0.0, "passed": False, "diagnostic": None, "oracleScriptError": False},
    }
    assert classify_episode_outcome(rec_clean_fail) == {
        "owner": "subject_fsq",
        "category": "task_goal_not_satisfied",
    }


def test_cli_subset_flag_and_episodes_jsonl_resume(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fsq_macarena_eval import cli, runner

    records = discover_tasks(MACARENA_REPO, subsets=("macarena",))
    assert len(records) == 49

    # Pre-populate episodes.jsonl with 1 completed task and 1 oracle_script_error task
    camp_dir = tmp_path / "camp"
    camp_dir.mkdir(parents=True)
    t_done, t_retry = records[0], records[1]
    existing_rows = [
        {
            "subset": t_done.subset,
            "taskId": t_done.task_id,
            "visualProviderUploadAllowed": False,
            "oracle": {"score": 1.0, "passed": True},
            "attribution": {"owner": "none", "category": "passed"},
            "worker": {"status": "completed", "actionBudget": {"launchAppCalls": []}},
        },
        {
            "subset": t_retry.subset,
            "taskId": t_retry.task_id,
            "visualProviderUploadAllowed": False,
            "oracle": {"score": 0.0, "passed": False, "oracleScriptError": True},
            "attribution": {"owner": "benchmark_evaluator", "category": "oracle_script_error"},
            "worker": {"status": "completed", "actionBudget": {"launchAppCalls": []}},
        },
    ]
    (camp_dir / "episodes.jsonl").write_text(
        "\n".join(json.dumps(r) for r in existing_rows) + "\n",
        encoding="utf-8",
    )

    executed_ids: list[str] = []

    def fake_single(**kwargs: Any) -> dict[str, Any]:
        t = kwargs["task"]
        executed_ids.append(t.task_id)
        return {
            "subset": t.subset,
            "taskId": t.task_id,
            "oracle": {"score": 1.0, "passed": True},
            "attribution": {"owner": "none", "category": "passed"},
            "worker": {"status": "completed", "actionBudget": {"launchAppCalls": []}},
            "elapsedSeconds": 1.0,
        }

    monkeypatch.setattr(runner, "run_single_task_episode", fake_single)
    monkeypatch.setattr(runner, "verify_frozen_wheels", lambda: {"schemaVersion": 1, "wheels": []})

    rc = cli.main(
        [
            "--state-dir",
            str(tmp_path / "state"),
            "run",
            "--subset",
            "macarena",
            "--task-ids",
            t_done.task_id,
            t_retry.task_id,
            "--workers",
            "1",
            "--campaign-dir",
            str(camp_dir),
        ]
    )
    assert rc == 0
    # t_done skipped via episodes.jsonl; t_retry re-executed because previous run was oracle_script_error
    assert executed_ids == [t_retry.task_id]


def test_start_guest_services_never_falls_back_to_ssh_nohup_and_enforces_tcc_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import io
    from PIL import Image
    from fsq_macarena_eval.provision import build_aqua_launchagent_plist_bytes
    from fsq_macarena_eval.utm_supervisor import (
        ClonedVMHandle,
        DualSlotUTMSupervisor,
        UTMSupervisorError,
    )

    plist_doc = plistlib.loads(build_aqua_launchagent_plist_bytes())
    assert plist_doc["Label"] == "com.fsq.macarena-server"
    assert plist_doc["LimitLoadToSessionType"] == ["Aqua"]
    assert plist_doc["RunAtLoad"] is True
    assert plist_doc["KeepAlive"] is True

    sup = DualSlotUTMSupervisor(state_dir=tmp_path / "state", utm_documents_dir=tmp_path / "vm_golden")
    ssh_commands: list[str] = []

    class DummyHandle(ClonedVMHandle):
        def ssh_run(self, remote_cmd: str, **kwargs: Any) -> Any:
            ssh_commands.append(remote_cmd)
            assert "nohup bash -lc 'source" not in remote_cmd
            assert "MISSING_AQUA_LAUNCHAGENT_PLIST" in remote_cmd
            return SimpleNamespace(returncode=0, stdout="", stderr="")

    handle = DummyHandle(
        slot_id=0,
        base_vm_name="osworld",
        vm_name="fsq-slot0-test",
        mac_address="02:a0:00:00:00:01",
        ip_address="192.168.64.55",
        private_key=sup.private_key,
        host_forward_proc=SimpleNamespace(poll=lambda: None),  # type: ignore[arg-type]
        host_server_port=15000,
    )
    monkeypatch.setattr(sup, "wait_for_guest_http_server", lambda *a, **kw: None)
    monkeypatch.setattr("fsq_macarena_eval.utm_supervisor.time.sleep", lambda s: None)

    def make_png_bytes(rgb: tuple[int, int, int]) -> bytes:
        buf = io.BytesIO()
        Image.new("RGB", (400, 300), color=rgb).save(buf, format="PNG")
        return buf.getvalue()

    wallpaper_png = make_png_bytes((67, 59, 41))
    window_open_png = make_png_bytes((235, 235, 238))

    # Case A: `:5000` returns window title, but `/screenshot` returns wallpaper-only -> MUST fail hard gate!
    import requests

    monkeypatch.setattr(
        requests,
        "post",
        lambda url, json=None, timeout=0: SimpleNamespace(
            status_code=200,
            json=lambda: {"returncode": 0, "output": "Documents\n"},
            text="Documents\n",
        ),
    )
    monkeypatch.setattr(
        requests,
        "get",
        lambda url, timeout=0: SimpleNamespace(status_code=200, content=wallpaper_png),
    )
    with pytest.raises(UTMSupervisorError, match="ScreenCapture TCC missing"):
        sup.verify_guest_aqua_tcc_readiness(handle, timeout_seconds=0.05)

    # Case B: `window 1` probe fails (rc=1 / assistive access denied) -> MUST fail hard gate!
    monkeypatch.setattr(
        requests,
        "post",
        lambda url, json=None, timeout=0: SimpleNamespace(
            status_code=200,
            json=lambda: {"returncode": 1, "output": "System Events got an error: osascript is not allowed assistive access."},
            text="",
        ),
    )
    with pytest.raises(UTMSupervisorError, match="Accessibility window-1 probe failed"):
        sup.verify_guest_aqua_tcc_readiness(handle, timeout_seconds=0.1)

    # Case C: Both `window 1` (`Documents`, rc=0) and non-wallpaper `/screenshot` succeed -> PASS!
    shots = [wallpaper_png, window_open_png]
    monkeypatch.setattr(
        requests,
        "post",
        lambda url, json=None, timeout=0: SimpleNamespace(
            status_code=200,
            json=lambda: {"returncode": 0, "output": "Documents\n"},
            text="Documents\n",
        ),
    )
    monkeypatch.setattr(
        requests,
        "get",
        lambda url, timeout=0: SimpleNamespace(status_code=200, content=shots.pop(0) if shots else window_open_png),
    )
    gate = sup.start_guest_services(handle, verify_tcc=True)
    assert gate is not None
    assert gate["windowTitle"] == "Documents"
    assert gate["returncode"] == 0
    assert gate["baselineMeanAbsDiff"] > 100.0


def test_setup_convergence_frontmost_resolution_and_patched_oracle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from fsq_macarena_eval.evaluator import (
        apply_oracle_mode_to_task_config,
        parse_lsappinfo_frontmost,
    )
    from fsq_macarena_eval.fsq_worker import resolve_effective_bundle_id

    parsed = parse_lsappinfo_frontmost(
        '"CFBundleIdentifier"="com.apple.iWork.Pages"\n"LSDisplayName"="Pages"\n"pid"=4312\n'
    )
    assert parsed == {
        "bundleId": "com.apple.iWork.Pages",
        "appName": "Pages",
        "pid": 4312,
    }

    # Native FSQ 0.3.6 auto-frontmost passthrough forwards `bundle_id="auto"` and records detected Pages telemetry
    res_auto = resolve_effective_bundle_id(
        "auto",
        frontmost_detector=lambda: {
            "resolvedBundleId": "com.apple.iWork.Pages",
            "appName": "Pages",
            "source": "lsappinfo_front",
        },
    )
    assert res_auto["effectiveBundleId"] == "auto"
    assert res_auto["detectedFrontmostBundleId"] == "com.apple.iWork.Pages"
    assert res_auto["resolutionSource"] == "native_fsq_auto(lsappinfo_front)"

    # Falls back to setup_frontmost_hint when concrete resolution is requested (`pass_native_auto=False`) or recorded
    res_hint = resolve_effective_bundle_id(
        "auto",
        frontmost_detector=lambda: {
            "resolvedBundleId": "com.apple.finder",
            "appName": None,
            "source": "fallback",
        },
        initial_frontmost_hint="com.apple.ScriptEditor2",
        pass_native_auto=False,
    )
    assert res_hint["effectiveBundleId"] == "com.apple.ScriptEditor2"
    assert res_hint["resolutionSource"] == "setup_frontmost_hint"
    # Wait for setup convergence polls until activeSetupChildren == 0 and frontmost bundle stabilizes
    env = BoundMacArenaEnv(
        macarena_repo=MACARENA_REPO,
        vm_ip="127.0.0.1",
        server_port=5000,
        cache_dir_base=tmp_path / "cache",
    )
    poll_states = [
        {"activeSetupChildren": 1, "bundleId": "com.apple.finder", "appName": "Finder", "pid": 300},
        {"activeSetupChildren": 0, "bundleId": "com.apple.iWork.Numbers", "appName": "Numbers", "pid": 811},
        {"activeSetupChildren": 0, "bundleId": "com.apple.iWork.Numbers", "appName": "Numbers", "pid": 811},
    ]
    monkeypatch.setattr(
        env,
        "query_guest_frontmost_app_and_setup_state",
        lambda: poll_states.pop(0) if poll_states else {"activeSetupChildren": 0, "bundleId": "com.apple.iWork.Numbers", "appName": "Numbers", "pid": 811},
    )
    monkeypatch.setattr("fsq_macarena_eval.evaluator.time.sleep", lambda s: None)
    conv = env.wait_for_setup_convergence(has_pre_command=True, min_settle_seconds=0.0, max_wait_seconds=10.0)
    assert conv["converged"] is True
    assert conv["polls"] == 3
    assert conv["frontmostBundleId"] == "com.apple.iWork.Numbers"

    # Verify strict-upstream vs patched-oracle isolation on 7b655b3b & 957ae859
    records = {r.task_id: r for r in discover_tasks(MACARENA_REPO, subsets=("macarena", "macosworld"))}
    t_pdf = records["7b655b3b-5c21-41cb-a7ba-52cfe076e92f"]
    strict_cfg, strict_meta = apply_oracle_mode_to_task_config(t_pdf.config, "strict-upstream")
    assert strict_meta is None
    assert strict_cfg is t_pdf.config

    patched_cfg, patched_meta = apply_oracle_mode_to_task_config(t_pdf.config, "patched-oracle")
    assert patched_meta is not None
    assert "reorder_pre_command_before_upload" in patched_meta["appliedPatches"]

    t_key = records["957ae859-e96e-74b5-3754-2efd2bcdf027"]
    patched_key, key_meta = apply_oracle_mode_to_task_config(t_key.config, "patched-oracle")
    assert key_meta is not None
    assert "120|15" in patched_key["evaluator"][0][0]


def test_golden_regression_36_manifest_and_cli_task_manifest_ordering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from fsq_macarena_eval import cli, runner
    from fsq_macarena_eval.manifest import load_task_ids_from_manifest

    manifest_path = Path(__file__).resolve().parent.parent / "manifests" / "golden_regression_36.json"
    assert manifest_path.is_file()
    task_ids = load_task_ids_from_manifest(manifest_path)
    assert len(task_ids) == 36
    assert len(set(task_ids)) == 36

    all_200 = {r.task_id: r for r in discover_tasks(MACARENA_REPO, subsets=("macarena", "macosworld"))}
    assert set(task_ids).issubset(all_200.keys())

    captured: dict[str, Any] = {}

    def fake_run_campaign(**kwargs: Any) -> dict[str, Any]:
        captured["task_ids"] = [t.task_id for t in kwargs["tasks"]]
        captured["oracle_mode"] = kwargs["oracle_mode"]
        captured["initial_bundle_id"] = kwargs["initial_bundle_id"]
        return {"schemaVersion": 1, "totalTasksRequested": len(kwargs["tasks"])}

    monkeypatch.setattr(cli, "run_campaign", fake_run_campaign)
    rc = cli.main(
        [
            "--state-dir",
            str(tmp_path / "state"),
            "run",
            "--task-manifest",
            str(manifest_path),
            "--oracle-mode",
            "patched-oracle",
            "--workers",
            "2",
            "--campaign-dir",
            str(tmp_path / "reg36"),
        ]
    )
    assert rc == 0
    assert captured["task_ids"] == task_ids
    assert captured["oracle_mode"] == "patched-oracle"
    assert captured["initial_bundle_id"] == "auto"

    targeted_15_path = Path(__file__).resolve().parent.parent / "manifests" / "targeted_iwork_lo_15.json"
    assert targeted_15_path.is_file()
    t15_ids = load_task_ids_from_manifest(targeted_15_path)
    assert len(t15_ids) == 15
    assert len(set(t15_ids)) == 15
    assert set(t15_ids).issubset(all_200.keys())
