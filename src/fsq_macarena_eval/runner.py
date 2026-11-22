"""Concurrent dual-slot campaign runner and strict diagnostic taxonomy.

Separates Subject (`FSQ` / `appium-connect-agent` / `Mac2`) behavior from
Benchmark (`MacArena` VM / setup / evaluator / proxy) infrastructure.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import queue
import shlex
import threading
import time
from pathlib import Path
from typing import Any

from .evaluator import BoundMacArenaEnv, OracleMode
from .manifest import (
    AUTO_FRONTMOST_BUNDLE_ID,
    FROZEN_MODEL,
    FROZEN_PROVIDER,
    default_frozen_wheels,
    TaskRecord,
    verify_frozen_wheels,
)
from .utm_supervisor import ClonedVMHandle, DualSlotUTMSupervisor


def _verify_guest_freeze(handle: ClonedVMHandle) -> dict[str, Any]:
    expected = {
        spec.package_name: (spec.version, spec.expected_sha256)
        for spec in default_frozen_wheels()
    }
    script = f"""import hashlib, importlib.metadata as md, json
from pathlib import Path
from urllib.parse import unquote, urlsplit

result = {{}}
for name, (version, sha) in {expected!r}.items():
    distribution = md.distribution(name)
    if distribution.version != version:
        raise RuntimeError(f'{{name}}: expected {{version}}, installed {{distribution.version}}')
    origin = json.loads(distribution.read_text('direct_url.json') or '{{}}')
    url = urlsplit(origin.get('url', ''))
    if url.scheme != 'file' or origin.get('archive_info', {{}}).get('hashes', {{}}).get('sha256') != sha:
        raise RuntimeError(f'{{name}}: installed wheel provenance mismatch')
    with Path(unquote(url.path)).open('rb') as archive:
        if hashlib.file_digest(archive, 'sha256').hexdigest() != sha:
            raise RuntimeError(f'{{name}}: guest wheel archive digest mismatch')
    result[name] = {{'version': version, 'sha256': sha}}
lxml = md.version('lxml')
if lxml != '6.1.0':
    raise RuntimeError(f'lxml: expected 6.1.0, installed {{lxml}}')
result['lxml'] = {{'version': lxml}}
print(json.dumps(result))
"""
    out = handle.ssh_run(
        f"/Users/admin/.fsq-eval-venv/bin/python -c {shlex.quote(script)}",
        timeout=15.0,
        retries=0,
    )
    return json.loads(out.stdout)


def classify_episode_outcome(record: dict[str, Any]) -> dict[str, str]:
    """Strictly separate Subject (`FSQ`/`appium-connect-agent`) vs Benchmark (`MacArena`/VM) issues."""
    if record.get("vmAcquireError") or record.get("hostTransportError"):
        return {
            "owner": "benchmark_environment",
            "category": "vm_lifecycle_or_network_error",
        }
    if record.get("setupError"):
        return {
            "owner": "benchmark_environment",
            "category": "task_setup_error",
        }
    if record.get("evaluateError"):
        return {
            "owner": "benchmark_evaluator",
            "category": "oracle_evaluation_error",
        }
    oracle = record.get("oracle") or {}
    if oracle.get("passed") is True:
        return {"owner": "none", "category": "passed"}
    diag_raw = oracle.get("diagnostic")
    diag_payload = oracle.get("diagnosticPayload")
    if diag_payload is None and isinstance(diag_raw, str) and diag_raw.strip():
        try:
            maybe_dict = json.loads(diag_raw)
            if isinstance(maybe_dict, dict):
                diag_payload = maybe_dict
        except Exception:
            diag_payload = {"status": "error", "raw": diag_raw}
    if oracle.get("oracleScriptError") is True or (
        isinstance(diag_payload, dict)
        and (
            diag_payload.get("returncode") == -1
            or str(diag_payload.get("status") or "").lower() == "error"
        )
    ):
        return {
            "owner": "benchmark_evaluator",
            "category": "oracle_script_error",
        }
    worker = record.get("worker") or {}
    budget = worker.get("actionBudget") or {}
    launch_calls = budget.get("launchAppCalls") or []
    failed_launches = [c for c in launch_calls if not c.get("succeeded")]

    if worker.get("status") == "deadline":
        return {"owner": "subject_fsq", "category": "episode_deadline_exceeded"}
    if worker.get("terminationReason") == "action_budget":
        return {"owner": "subject_fsq", "category": "action_budget_exhausted"}
    if worker.get("status") != "completed":
        return {"owner": "subject_fsq", "category": "worker_or_harness_error"}
    if failed_launches:
        return {"owner": "subject_fsq_or_mac2", "category": "launch_app_activation_failed"}
    return {"owner": "subject_fsq", "category": "task_goal_not_satisfied"}


def _agent_signaled_fail_or_infeasible(worker_response: dict[str, Any]) -> bool:
    main_ans = worker_response.get("mainAnswer") or {}
    runner_status = str(main_ans.get("runnerStatus") or "").lower()
    summary = str(main_ans.get("summary") or "").lower()
    fsq_status = str((worker_response.get("fsq") or {}).get("status") or "").lower()
    if runner_status in {"failed", "skipped", "cancelled", "incomplete"}:
        if any(tok in summary for tok in ("infeasible", "impossible", "cannot be completed", "cannot complete")):
            return True
    if fsq_status == "failed" and "infeasible" in summary:
        return True
    return False


def run_single_task_episode(
    *,
    task: TaskRecord,
    slot_id: int,
    supervisor: DualSlotUTMSupervisor,
    macarena_repo: Path,
    campaign_dir: Path,
    max_actions: int = 60,
    max_turns: int = 100,
    reasoning_effort: str = "mid",
    episode_timeout_seconds: float = 900.0,
    initial_bundle_id: str = AUTO_FRONTMOST_BUNDLE_ID,
    oracle_mode: OracleMode = "strict-upstream",
    host_fsq_config_dir: Path = Path("~/.fsq").expanduser(),
    visual_provider_upload_allowed: bool = False,
) -> dict[str, Any]:
    episode_dir = (campaign_dir / "episodes" / task.subset / task.category / task.task_id).resolve()
    episode_dir.mkdir(parents=True, exist_ok=True)
    started_unix = time.time()
    record: dict[str, Any] = {
        "schemaVersion": 1,
        "subset": task.subset,
        "category": task.category,
        "taskId": task.task_id,
        "baseVm": task.base_vm,
        "slotId": slot_id,
        "instruction": task.instruction,
        "initialBundleId": initial_bundle_id,
        "oracleMode": oracle_mode,
        "visualProviderUploadAllowed": visual_provider_upload_allowed,
        "relatedAppsMetadataNotPassedToSubject": task.config.get("related_apps", []),
        "startedAtUnix": started_unix,
    }

    handle: ClonedVMHandle | None = None
    try:
        handle = supervisor.acquire_disposable_vm(
            slot_id=slot_id,
            base_vm_name=task.base_vm,
            task_id=task.task_id,
        )
        record["guestFreeze"] = _verify_guest_freeze(handle)
        record["vm"] = {
            "vmName": handle.vm_name,
            "baseBundle": str(supervisor.utm_documents_dir / f"{task.base_vm}.utm"),
            "ipAddress": handle.ip_address,
            "macAddress": handle.mac_address,
            "guestProxyUrl": handle.guest_proxy_url,
            "hostServerPort": handle.host_server_port,
            "hostChromiumPort": handle.host_chromium_port,
            "hostVlcPort": handle.host_vlc_port,
            "tccReadiness": handle.tcc_readiness_receipt,
        }

        try:
            handle.ssh_run(
                "mkdir -p /Users/admin/.fsq/auth && chmod 700 /Users/admin/.fsq /Users/admin/.fsq/auth",
                timeout=30.0,
            )
            cfg_file = host_fsq_config_dir / "config.yaml"
            if cfg_file.is_file():
                handle.scp_to_guest(cfg_file, "/Users/admin/.fsq/config.yaml", timeout=30.0)
                handle.ssh_run("chmod 600 /Users/admin/.fsq/config.yaml", timeout=20.0)
            auth_dir = host_fsq_config_dir / "auth"
            if auth_dir.is_dir():
                for auth_item in sorted(auth_dir.glob("*.json")):
                    handle.scp_to_guest(auth_item, f"/Users/admin/.fsq/auth/{auth_item.name}", timeout=30.0)
                handle.ssh_run("chmod 600 /Users/admin/.fsq/auth/*.json 2>/dev/null || true", timeout=20.0)
        except BaseException as exc:
            record["hostTransportError"] = {"type": type(exc).__name__, "message": str(exc)[:500]}
            raise
        env = BoundMacArenaEnv(
            macarena_repo=macarena_repo,
            vm_ip="127.0.0.1",
            server_port=handle.host_server_port,
            chromium_port=handle.host_chromium_port,
            vlc_port=handle.host_vlc_port,
            cache_dir_base=campaign_dir / "eval_cache",
            enable_proxy=False,
            oracle_mode=oracle_mode,
        )
        try:
            setup_receipt = env.setup_task(task.config, oracle_mode=oracle_mode)
            record["setup"] = setup_receipt
        except BaseException as exc:
            record["setupError"] = {"type": type(exc).__name__, "message": str(exc)[:500]}
            raise

        # Prepare isolated guest worker request (`bundleId` defaults to `"auto"` -> attaches post-setup frontmost app)
        guest_ep_dir = f"/Users/admin/fsq_runs/{task.task_id}"
        worker_req: dict[str, Any] = {
            "schemaVersion": 1,
            "workspace": f"{guest_ep_dir}/workspace",
            "outputDir": f"{guest_ep_dir}/output",
            "taskId": task.task_id,
            "goal": task.instruction,
            "bundleId": initial_bundle_id,
            "maxActions": max_actions,
            "businessDeadlineMonotonic": 0.0,  # overridden on guest via --duration-seconds
            "provider": FROZEN_PROVIDER,
            "visualProviderUploadAllowed": visual_provider_upload_allowed,
            "model": FROZEN_MODEL,
            "runtimeProfile": {
                "maxTurns": max_turns,
                "reasoningEffort": reasoning_effort,
                "tracingEnabled": True,
            },
        }
        if setup_receipt.get("frontmostBundleId"):
            worker_req["initialFrontmostHint"] = setup_receipt["frontmostBundleId"]
        local_req_path = episode_dir / "worker-request.json"
        local_req_path.write_text(json.dumps(worker_req, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        handle.ssh_run(f"mkdir -p {guest_ep_dir}", timeout=15.0)
        handle.scp_to_guest(local_req_path, f"{guest_ep_dir}/worker-request.json", timeout=30.0)

        proxy_exports = ""
        if handle.guest_proxy_url:
            proxy_exports = (
                f"export HTTP_PROXY={handle.guest_proxy_url} "
                f"HTTPS_PROXY={handle.guest_proxy_url} "
                f"ALL_PROXY={handle.guest_proxy_url} "
                "NO_PROXY=127.0.0.1,localhost,::1; "
            )
        worker_cmd = (
            f"{proxy_exports}"
            "export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; "
            "/Users/admin/.fsq-eval-venv/bin/python -m fsq_macarena_eval.fsq_worker run "
            f"--request {guest_ep_dir}/worker-request.json "
            f"--output {guest_ep_dir}/worker-response.json "
            f"--duration-seconds {episode_timeout_seconds}"
        )
        worker_ssh = handle.ssh_run(
            worker_cmd,
            timeout=episode_timeout_seconds + 90.0,
            check=False,
        )
        record["workerProcess"] = {
            "returnCode": worker_ssh.returncode,
            "stderrTail": worker_ssh.stderr[-1000:] if worker_ssh.stderr else "",
        }

        local_resp_path = episode_dir / "worker-response.json"
        handle.scp_from_guest(
            f"{guest_ep_dir}/worker-response.json",
            local_resp_path,
            timeout=60.0,
        )
        # Pull guest output directory (audit jsonl + task result) for offline diagnostics
        guest_out_copy = episode_dir / "guest_output"
        try:
            handle.scp_from_guest(
                f"{guest_ep_dir}/output",
                guest_out_copy,
                recursive=True,
                timeout=120.0,
            )
        except Exception:
            pass

        worker_response = json.loads(local_resp_path.read_text(encoding="utf-8"))
        record["worker"] = worker_response

        # Capture post-execution screenshot from MacArena server before grading
        try:
            final_png = env.controller.get_screenshot()
            if isinstance(final_png, (bytes, bytearray)) and final_png:
                (episode_dir / "final_screen.png").write_bytes(final_png)
        except Exception:
            pass

        # Run upstream MacArena oracle evaluation strictly AFTER worker process exit
        try:
            record["oracle"] = env.evaluate_task(
                task.config,
                agent_reported_infeasible_or_fail=_agent_signaled_fail_or_infeasible(worker_response),
                oracle_mode=oracle_mode,
            )
        except BaseException as exc:
            record["evaluateError"] = {"type": type(exc).__name__, "message": str(exc)[:500]}
            raise
    except BaseException as exc:
        if "setupError" not in record and "evaluateError" not in record and "vm" not in record:
            record["vmAcquireError"] = {"type": type(exc).__name__, "message": str(exc)[:500]}
        record.setdefault("topLevelError", {"type": type(exc).__name__, "message": str(exc)[:500]})
    finally:
        if handle is not None:
            record["cleanup"] = supervisor.release_disposable_vm(handle)

    record["completedAtUnix"] = time.time()
    record["elapsedSeconds"] = round(record["completedAtUnix"] - started_unix, 2)
    record["attribution"] = classify_episode_outcome(record)
    (episode_dir / "episode-summary.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return record


def run_campaign(
    *,
    tasks: list[TaskRecord],
    supervisor: DualSlotUTMSupervisor,
    macarena_repo: Path,
    campaign_dir: Path,
    workers: int = 2,
    max_actions: int = 60,
    max_turns: int = 100,
    reasoning_effort: str = "mid",
    episode_timeout_seconds: float = 900.0,
    initial_bundle_id: str = AUTO_FRONTMOST_BUNDLE_ID,
    oracle_mode: OracleMode = "strict-upstream",
    resume: bool = True,
    visual_provider_upload_allowed: bool = False,
) -> dict[str, Any]:
    if workers not in (1, 2):
        raise ValueError("Apple Silicon Virtualization.framework supports --workers 1 or 2")
    wheel_manifest = verify_frozen_wheels()
    campaign_dir = campaign_dir.expanduser().resolve()
    campaign_dir.mkdir(parents=True, exist_ok=True)
    episodes_ledger_path = campaign_dir / "episodes.jsonl"
    legacy_ledger_path = campaign_dir / "results.jsonl"
    ledger_lock = threading.Lock()

    completed_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    if resume:
        for candidate in (legacy_ledger_path, episodes_ledger_path):
            if not candidate.is_file():
                continue
            for line in candidate.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                attr = row.get("attribution") or classify_episode_outcome(row)
                if (
                    "oracle" in row
                    and row.get("visualProviderUploadAllowed") is visual_provider_upload_allowed
                    and not row.get("vmAcquireError")
                    and not row.get("setupError")
                    and not row.get("evaluateError")
                    and attr.get("owner") not in {"benchmark_environment", "benchmark_evaluator"}
                ):
                    completed_by_key[(row["subset"], row["taskId"])] = row

    pending = [t for t in tasks if (t.subset, t.task_id) not in completed_by_key]

    slot_pool: queue.Queue[int] = queue.Queue()
    for slot_id in range(workers):
        slot_pool.put(slot_id)

    results: list[dict[str, Any]] = list(completed_by_key.values())

    def _worker_entry(task: TaskRecord) -> dict[str, Any]:
        slot_id = slot_pool.get()
        try:
            print(
                f"[smoke/run] slot={slot_id} START subset={task.subset} category={task.category} task={task.task_id} base_vm={task.base_vm}",
                flush=True,
            )
            ep = run_single_task_episode(
                task=task,
                slot_id=slot_id,
                supervisor=supervisor,
                macarena_repo=macarena_repo,
                campaign_dir=campaign_dir,
                max_actions=max_actions,
                max_turns=max_turns,
                reasoning_effort=reasoning_effort,
                episode_timeout_seconds=episode_timeout_seconds,
                initial_bundle_id=initial_bundle_id,
                oracle_mode=oracle_mode,
                visual_provider_upload_allowed=visual_provider_upload_allowed,
            )
            with ledger_lock:
                line_str = json.dumps(ep, sort_keys=True) + "\n"
                with episodes_ledger_path.open("a", encoding="utf-8") as fh:
                    fh.write(line_str)
                with legacy_ledger_path.open("a", encoding="utf-8") as fh:
                    fh.write(line_str)
            print(
                f"[smoke/run] slot={slot_id} DONE subset={task.subset} task={task.task_id} "
                f"score={(ep.get('oracle') or {}).get('score')} "
                f"attr={ep.get('attribution')} elapsed={ep.get('elapsedSeconds')}s",
                flush=True,
            )
            return ep
        finally:
            slot_pool.put(slot_id)

    started = time.time()
    if pending:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_worker_entry, t) for t in pending]
            for fut in concurrent.futures.as_completed(futs):
                results.append(fut.result())

    # Aggregate summary by subset and owner attribution
    by_subset: dict[str, dict[str, Any]] = {}
    attribution_counts: dict[str, int] = {}
    launch_new_session_false = 0
    launch_new_session_false_failed = 0

    for r in results:
        sub = r["subset"]
        bucket = by_subset.setdefault(
            sub, {"count": 0, "scoreSum": 0.0, "passed": 0}
        )
        bucket["count"] += 1
        score = float((r.get("oracle") or {}).get("score", 0.0))
        bucket["scoreSum"] += score
        if (r.get("oracle") or {}).get("passed"):
            bucket["passed"] += 1

        attr = r.get("attribution") or {}
        key = f"{attr.get('owner', 'unknown')}:{attr.get('category', 'unknown')}"
        attribution_counts[key] = attribution_counts.get(key, 0) + 1

        for lc in ((r.get("worker") or {}).get("actionBudget") or {}).get("launchAppCalls") or []:
            if not lc.get("newSession"):
                launch_new_session_false += 1
                if not lc.get("succeeded"):
                    launch_new_session_false_failed += 1

    for sub, bucket in by_subset.items():
        bucket["averageScore"] = round(bucket["scoreSum"] / max(1, bucket["count"]), 4)

    summary = {
        "schemaVersion": 1,
        "frozenWheels": wheel_manifest,
        "workers": workers,
        "initialBundleId": initial_bundle_id,
        "oracleMode": oracle_mode,
        "totalTasksRequested": len(tasks),
        "totalEpisodesRecorded": len(results),
        "bySubset": by_subset,
        "attributionCounts": attribution_counts,
        "launchAppActivationTelemetry": {
            "newSessionFalseCalls": launch_new_session_false,
            "newSessionFalseFailures": launch_new_session_false_failed,
        },
        "elapsedWallSeconds": round(time.time() - started, 2),
    }
    (campaign_dir / "campaign-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary
