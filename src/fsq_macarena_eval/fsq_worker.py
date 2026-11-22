"""Guest-side native FSQ macOS worker and preflight model probe.

Executed inside the disposable macOS UTM VM using the isolated guest venv containing
only the SHA256-verified frozen `fsq-agent` and `appium-connect-agent` wheels
(never editable checkouts).

Subcommands:
- `probe`: verify non-editable wheel provenance + run `test_model_provider_connection`
  and emit a `passed_native_responses` receipt.
- `run`: initialize an isolated canonical FSQ macOS workspace (`bundle_id="com.apple.finder"`),
  execute `DynamicExecutionService` through `BudgetedMacOSHarness`, record `launch_app`
  telemetry (`new_session` True/False), and persist full private execution receipts.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import importlib.metadata
import json
import math
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .fsq_native import (
    NativeDeadlineExceeded,
    NativeMacOSDispatchBudget,
    build_native_macos_harness_factory,
)

ANSWER_SOURCE = "agent_runtime.runner.tool_output.summary"
AUTO_FRONTMOST_BUNDLE_SENTINELS = frozenset({"auto", "frontmost", "__frontmost__"})
FALLBACK_INITIAL_BUNDLE_ID = "com.apple.finder"
_IGNORED_FRONTMOST_BUNDLES = frozenset(
    {
        "com.apple.loginwindow",
        "com.apple.SecurityAgent",
        "com.apple.UserNotificationCenter",
        "com.apple.CoreServicesUIAgent",
        "com.facebook.WebDriverAgentRunner.xctrunner",
    }
)


def detect_guest_frontmost_bundle_id(
    *,
    fallback_bundle_id: str = FALLBACK_INITIAL_BUNDLE_ID,
) -> dict[str, Any]:
    """Detect the currently active macOS GUI application's CFBundleIdentifier via `lsappinfo`."""
    try:
        front_res = subprocess.run(
            ["/usr/bin/lsappinfo", "front"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        asn = front_res.stdout.strip()
        if front_res.returncode == 0 and asn:
            info_res = subprocess.run(
                ["/usr/bin/lsappinfo", "info", "-only", "bundleid,name,pid", asn],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            m = re.search(r'"CFBundleIdentifier"\s*=\s*"([^"]+)"', info_res.stdout)
            name_m = re.search(r'"LSDisplayName"\s*=\s*"([^"]+)"', info_res.stdout)
            if m:
                bid = m.group(1).strip()
                if bid and bid not in _IGNORED_FRONTMOST_BUNDLES:
                    return {
                        "resolvedBundleId": bid,
                        "appName": name_m.group(1).strip() if name_m else None,
                        "source": "lsappinfo_front",
                    }
    except Exception:
        pass
    return {
        "resolvedBundleId": fallback_bundle_id,
        "appName": None,
        "source": "fallback",
    }

REQUIRED_RUN_FIELDS = frozenset(
    {
        "schemaVersion",
        "workspace",
        "outputDir",
        "taskId",
        "goal",
        "bundleId",
        "maxActions",
        "businessDeadlineMonotonic",
        "provider",
        "model",
        "runtimeProfile",
    }
)
OPTIONAL_RUN_FIELDS = frozenset(
    {"userConfigRoot", "initialFrontmostHint", "visualProviderUploadAllowed"}
)


def resolve_effective_bundle_id(
    requested_bundle_id: str | None,
    *,
    frontmost_detector: Callable[[], dict[str, Any]] = detect_guest_frontmost_bundle_id,
    initial_frontmost_hint: str | None = None,
    pass_native_auto: bool = True,
) -> dict[str, Any]:
    """Resolve worker `bundleId`: forwards `'auto'` natively to FSQ 0.3.6 (`frontmost_macos_app`) while recording telemetry."""
    normalized = requested_bundle_id.strip() if isinstance(requested_bundle_id, str) else ""
    if normalized and normalized.lower() not in AUTO_FRONTMOST_BUNDLE_SENTINELS:
        return {
            "requestedBundleId": requested_bundle_id,
            "effectiveBundleId": normalized,
            "detectedFrontmostBundleId": None,
            "resolutionSource": "explicit",
            "detectedAppName": None,
        }
    detected = frontmost_detector()
    resolved = detected.get("resolvedBundleId")
    source = detected.get("source", "lsappinfo_front")
    if (
        (not resolved or source == "fallback")
        and isinstance(initial_frontmost_hint, str)
        and initial_frontmost_hint.strip()
        and initial_frontmost_hint.strip() not in _IGNORED_FRONTMOST_BUNDLES
    ):
        resolved = initial_frontmost_hint.strip()
        source = "setup_frontmost_hint"
    detected_bundle = resolved or FALLBACK_INITIAL_BUNDLE_ID
    effective = "auto" if pass_native_auto else detected_bundle
    return {
        "requestedBundleId": requested_bundle_id,
        "effectiveBundleId": effective,
        "detectedFrontmostBundleId": detected_bundle,
        "resolutionSource": f"native_fsq_auto({source})" if pass_native_auto else source,
        "detectedAppName": detected.get("appName"),
    }

def _private_json(path: Path, payload: Any) -> dict[str, Any]:
    data = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
    finally:
        os.close(fd)
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sizeBytes": len(data),
        "visibility": "evaluator_private",
    }


def inspect_installed_distribution(dist_name: str) -> dict[str, Any]:
    """Verify an installed package is a non-editable wheel and return provenance."""
    dist = importlib.metadata.distribution(dist_name)
    direct_url_text = dist.read_text("direct_url.json")
    direct_url: dict[str, Any] | None = None
    editable = False
    if direct_url_text:
        direct_url = json.loads(direct_url_text)
        dir_info = direct_url.get("dir_info")
        if isinstance(dir_info, dict) and dir_info.get("editable") is True:
            editable = True
    if editable:
        raise ValueError(f"Subject package {dist_name} is installed editable; frozen wheel required")
    return {
        "name": dist.metadata["Name"],
        "version": dist.version,
        "editable": editable,
        "directUrl": direct_url,
    }


def verify_subject_distributions() -> dict[str, dict[str, Any]]:
    return {
        "fsq-agent": inspect_installed_distribution("fsq-agent"),
        "appium-connect-agent": inspect_installed_distribution("appium-connect-agent"),
    }


def run_native_model_probe(
    *,
    expected_provider: str,
    expected_model: str,
    user_config_root: Path | None = None,
) -> dict[str, Any]:
    """Verify frozen wheels + execute native FSQ model connection probe."""
    started_unix = time.time()
    distributions = verify_subject_distributions()
    from fsq_agent.providers import test_model_provider_connection

    probe_result = test_model_provider_connection(user_config_root=user_config_root)
    if probe_result.provider != expected_provider or probe_result.model != expected_model:
        raise ValueError(
            f"Native model probe mismatch: expected {expected_provider}/{expected_model}, "
            f"observed {probe_result.provider}/{probe_result.model}"
        )
    completed_unix = time.time()
    return {
        "schemaVersion": 1,
        "status": "passed_native_responses",
        "provider": probe_result.provider,
        "requestedModel": expected_model,
        "effectiveModel": probe_result.model,
        "durationSeconds": round(probe_result.duration_seconds, 4),
        "startedAtUnix": started_unix,
        "completedAtUnix": completed_unix,
        "distributions": distributions,
    }


def select_main_answer(
    task_result: dict[str, Any],
    *,
    validate_output: Callable[[Any], Any] | None = None,
) -> dict[str, Any]:
    """Extract main runner summary from canonical FSQ TaskResult."""

    def reject(status: str, reason: str) -> dict[str, Any]:
        return {"status": status, "source": ANSWER_SOURCE, "reason": reason}

    if not isinstance(task_result, dict):
        return reject("invalid", "task_result is not an object")
    steps = task_result.get("steps")
    if not isinstance(steps, list):
        return reject("invalid", "task_result.steps is not a list")
    runner_steps = [
        step
        for step in steps
        if isinstance(step, dict)
        and (step.get("tool_name") == "agent_runtime.runner" or step.get("action") == "agent_runtime.runner")
    ]
    if not runner_steps:
        return reject("missing", "no agent_runtime.runner step recorded")
    if len(runner_steps) > 1:
        return reject("invalid", "multiple agent_runtime.runner steps recorded")
    runner = runner_steps[0]
    tool_output = runner.get("tool_output")
    if not isinstance(tool_output, dict):
        return reject("missing", "runner step lacks structured tool_output")
    if validate_output is not None:
        try:
            validated = validate_output(tool_output)
            if hasattr(validated, "model_dump"):
                tool_output = validated.model_dump(mode="json")
        except Exception as exc:
            return reject("invalid", f"AgentFinalOutput validation failed: {type(exc).__name__}")
    summary = tool_output.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        return reject("missing", "runner tool_output.summary is empty")
    return {
        "status": "present",
        "source": ANSWER_SOURCE,
        "summary": summary,
        "runnerStatus": tool_output.get("status"),
    }


def validate_run_request(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Worker request must be a JSON object")
    unknown = set(value) - REQUIRED_RUN_FIELDS - OPTIONAL_RUN_FIELDS
    missing = REQUIRED_RUN_FIELDS - set(value)
    if missing or unknown:
        raise ValueError(f"Invalid worker request fields: missing={sorted(missing)} unknown={sorted(unknown)}")
    if value["schemaVersion"] != 1:
        raise ValueError("Unsupported worker request schemaVersion")
    for str_field in ("workspace", "outputDir", "taskId", "goal", "provider", "model"):
        if not isinstance(value[str_field], str) or not value[str_field].strip():
            raise ValueError(f"{str_field} must be a non-empty string")
    if value["bundleId"] is not None and (
        not isinstance(value["bundleId"], str) or not value["bundleId"].strip()
    ):
        raise ValueError("bundleId must be a non-empty string or null")
    if type(value["maxActions"]) is not int or value["maxActions"] <= 0:
        raise ValueError("maxActions must be a positive integer")
    deadline = value["businessDeadlineMonotonic"]
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
        raise ValueError("businessDeadlineMonotonic must be finite")
    if not isinstance(value["runtimeProfile"], dict):
        raise ValueError("runtimeProfile must be an object")
    if "visualProviderUploadAllowed" in value and type(value["visualProviderUploadAllowed"]) is not bool:
        raise ValueError("visualProviderUploadAllowed must be a JSON boolean")
    return dict(value)


@dataclasses.dataclass(frozen=True)
class NativeMacOSBindings:
    initialize_workspace: Callable[..., Any]
    workspace_init_request_type: Any
    load_settings: Callable[..., Any]
    agent_type: Any
    runtime_factory: Callable[..., Any]
    execution_service_type: Any
    execution_request_type: Any
    task_type: Any
    harness_factory_builder: Callable[..., Any]
    validate_output: Callable[[Any], Any] | None = None


def load_native_macos_bindings() -> NativeMacOSBindings:
    verify_subject_distributions()
    from fsq_agent.adapters.coding_agent import create_coding_agent_runtime
    from fsq_agent.agent import FsqAgent
    from fsq_agent.application import WorkspaceInitializeRequest, initialize_workspace
    from fsq_agent.config import load_workspace_platform_settings
    from fsq_agent.execution.dynamic import DynamicExecutionRequest, DynamicExecutionService
    from fsq_agent.models import AgentFinalOutput, Task

    return NativeMacOSBindings(
        initialize_workspace=initialize_workspace,
        workspace_init_request_type=WorkspaceInitializeRequest,
        load_settings=load_workspace_platform_settings,
        agent_type=FsqAgent,
        runtime_factory=create_coding_agent_runtime,
        execution_service_type=DynamicExecutionService,
        execution_request_type=DynamicExecutionRequest,
        task_type=Task,
        harness_factory_builder=build_native_macos_harness_factory,
        validate_output=AgentFinalOutput.model_validate,
    )


def _configure_macos_workspace_and_settings(
    request: dict[str, Any],
    bindings: NativeMacOSBindings,
) -> Any:
    workspace = Path(request["workspace"]).expanduser().resolve()
    workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
    user_cfg: Path | None = None
    if "userConfigRoot" in request and request["userConfigRoot"] is not None:
        user_cfg = Path(request["userConfigRoot"]).expanduser().resolve()

    bundle_resolution = resolve_effective_bundle_id(
        request.get("bundleId"),
        initial_frontmost_hint=request.get("initialFrontmostHint"),
    )
    effective_bundle_id = bundle_resolution["effectiveBundleId"]

    config_file = workspace / ".fsq" / "config" / "config.macos.yaml"
    if not config_file.exists():
        init_kwargs: dict[str, Any] = {
            "current_directory": workspace,
            "platform": "macos",
            "bundle_id": effective_bundle_id,
        }
        if user_cfg is not None:
            init_kwargs["user_config_root"] = user_cfg
        bindings.initialize_workspace(bindings.workspace_init_request_type(**init_kwargs))

    load_kwargs: dict[str, Any] = {}
    if user_cfg is not None:
        load_kwargs["user_config_root"] = user_cfg
    settings = bindings.load_settings(workspace, "macos", **load_kwargs).model_copy(deep=True)
    if (
        settings.harness.platform != "macos"
        or settings.harness.macos.backend != "appium_connect_agent"
    ):
        raise ValueError("Worker requires native macOS appium_connect_agent Harness")
    if settings.harness.macos.bundle_id not in (effective_bundle_id, None):
        raise ValueError(
            f"Workspace bundle_id {settings.harness.macos.bundle_id!r} != effective {effective_bundle_id!r}"
        )
    if hasattr(settings.harness.macos, "skip_app_kill"):
        settings.harness.macos.skip_app_kill = True
    # Authorization comes only from the host-generated run request, not the goal,
    # workspace or model. Treat omitted permission as denial.
    visual_policy = getattr(settings.harness.macos, "visual_assertion_policy", None)
    allow_upload = request.get("visualProviderUploadAllowed", False)
    if visual_policy is not None:
        update = {"allow_provider_upload": allow_upload}
        if allow_upload:
            update["frame_sensitivity"] = "non_sensitive"
        settings.harness.macos.visual_assertion_policy = visual_policy.model_copy(update=update)
    elif allow_upload:
        raise ValueError("Installed native FSQ does not expose a macOS visual policy")

    profile = request["runtimeProfile"]
    if "maxTurns" in profile:
        settings.agent_runtime.max_turns = int(profile["maxTurns"])
    if "reasoningEffort" in profile:
        settings.agent_runtime.reasoning_effort = profile["reasoningEffort"]
    if "tracingEnabled" in profile:
        settings.agent_runtime.tracing_enabled = bool(profile["tracingEnabled"])
    if "pageSourceMaxDepth" in profile:
        settings.harness.macos.page_source_max_depth = int(profile["pageSourceMaxDepth"])
    if "actionTimeoutSeconds" in profile:
        settings.harness.macos.action_timeout_seconds = int(profile["actionTimeoutSeconds"])
    return settings, bundle_resolution


async def execute_worker(
    value: Any,
    *,
    bindings: NativeMacOSBindings | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    request = validate_run_request(value)
    output = Path(request["outputDir"]).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    budget = NativeMacOSDispatchBudget(
        request["maxActions"],
        request["businessDeadlineMonotonic"],
        clock=clock,
        journal=output / "native-action-audit.jsonl",
    )
    started_unix = time.time()
    response: dict[str, Any] = {
        "schemaVersion": 1,
        "status": "failed",
        "taskId": request["taskId"],
        "startedAtUnix": started_unix,
        "mainAnswer": {
            "status": "missing",
            "source": ANSWER_SOURCE,
            "reason": "Complete FSQ execution has not returned",
        },
        "fsq": {"taskResult": None, "verification": None, "status": None},
        "nativeTarget": {
            "requestedProvider": request["provider"],
            "requestedModel": request["model"],
            "effectiveProvider": None,
            "effectiveModel": None,
            "bundleId": request["bundleId"],
        },
    }
    try:
        budget.check_deadline()
        native = bindings if bindings is not None else load_native_macos_bindings()
        settings, bundle_resolution = _configure_macos_workspace_and_settings(request, native)
        response["nativeTarget"].update(
            {
                "effectiveProvider": settings.agent_runtime.provider,
                "effectiveModel": settings.agent_runtime.model,
                "backend": settings.harness.macos.backend,
                "requestedBundleId": request["bundleId"],
                "bundleId": settings.harness.macos.bundle_id,
                "detectedFrontmostBundleId": bundle_resolution.get("detectedFrontmostBundleId"),
                "bundleResolutionSource": bundle_resolution["resolutionSource"],
                "detectedFrontmostAppName": bundle_resolution["detectedAppName"],
                "maxTurns": settings.agent_runtime.max_turns,
                "reasoningEffort": settings.agent_runtime.reasoning_effort,
                "tracingEnabled": settings.agent_runtime.tracing_enabled,
                "pageSourceMaxDepth": settings.harness.macos.page_source_max_depth,
                "actionTimeoutSeconds": settings.harness.macos.action_timeout_seconds,
                "skipAppKill": getattr(settings.harness.macos, "skip_app_kill", None),
            }
        )
        if (
            settings.agent_runtime.provider != request["provider"]
            or settings.agent_runtime.model != request["model"]
        ):
            response["error"] = {
                "type": "NativeTargetMismatch",
                "reason": "effective_provider_model_mismatch",
            }
            raise ValueError("Effective native provider/model mismatch")

        response["fsq"]["nativeRunsRoot"] = {
            "path": str(settings.output.runs_dir.resolve()),
            "visibility": "evaluator_private",
        }
        harness_factory = native.harness_factory_builder(settings, budget)
        agent = native.agent_type.from_settings(
            settings,
            runtime_factory=native.runtime_factory,
            harness_factory=harness_factory,
        )
        task = native.task_type(
            id=request["taskId"],
            name=request["goal"],
            description=request["goal"],
            planning_reference_kind="goal",
            planning_reference_text=request["goal"],
        )
        service = native.execution_service_type(agent=agent)
        result = await service.execute(
            native.execution_request_type(
                task=task,
                settings=settings,
                record=False,
                cancellation_check=budget.check_deadline,
            )
        )
        task_result = result.task_result.model_dump(mode="json")
        verification = task_result.get("verification")
        budget.receipt(
            {
                "event": "native_execution_returned",
                "taskId": request["taskId"],
                "nativeTaskId": task_result.get("task_id"),
                "taskStatus": task_result.get("status"),
                "verificationObserved": isinstance(verification, dict),
                "verificationStatus": (
                    verification.get("status") if isinstance(verification, dict) else None
                ),
            }
        )
        report_info = task_result.get("report")
        response["fsq"] = {
            "taskResult": _private_json(output / "fsq-task-result.private.json", task_result),
            "verification": _private_json(
                output / "fsq-verification.private.json", verification
            ),
            "status": task_result.get("status"),
            "completeDynamicExecutionReturned": True,
            "nativeRunsRoot": {
                "path": str(settings.output.runs_dir.resolve()),
                "visibility": "evaluator_private",
            },
            "nativeReport": {
                "path": report_info.get("path") if isinstance(report_info, dict) else None,
                "visibility": "evaluator_private",
            },
        }
        response["mainAnswer"] = select_main_answer(
            task_result, validate_output=native.validate_output
        )
        budget.check_deadline()
        response["status"] = "completed"
    except BaseException as exc:
        deadline = isinstance(exc, NativeDeadlineExceeded) or clock() >= budget.deadline
        response["status"] = "deadline" if deadline else "failed"
        response.setdefault(
            "error",
            {
                "type": type(exc).__name__,
                "message": str(exc)[:500],
                "reason": "business_deadline" if deadline else "native_worker_failure",
            },
        )

    response["completedAtUnix"] = time.time()
    snapshot = budget.snapshot()
    response["actionBudget"] = snapshot
    response["terminationReason"] = (
        "deadline"
        if response["status"] == "deadline"
        else "action_budget"
        if any(event.get("reason") == "action_budget" for event in snapshot["events"])
        else "native_execution_returned"
        if response["fsq"].get("completeDynamicExecutionReturned")
        else "native_worker_failure"
    )
    response["cleanup"] = {
        "closeReceipts": [
            event for event in snapshot["events"] if event["event"].startswith("close_")
        ],
        "vmRestored": False,
        "workerProcessExitRequiredBeforeOracle": True,
    }
    if budget.journal is not None and budget.journal.exists():
        raw_audit = budget.journal.read_bytes()
        response["actionAudit"] = {
            "path": str(budget.journal),
            "sha256": hashlib.sha256(raw_audit).hexdigest(),
            "sizeBytes": len(raw_audit),
            "visibility": "evaluator_private",
        }
    return response


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    probe_parser = subparsers.add_parser("probe", help="Run native model & frozen wheel probe")
    probe_parser.add_argument("--provider", required=True)
    probe_parser.add_argument("--model", required=True)
    probe_parser.add_argument("--user-config-root", type=Path, default=None)
    probe_parser.add_argument("--output", required=True, type=Path)

    run_parser = subparsers.add_parser("run", help="Execute a single MacArena task via native FSQ")
    run_parser.add_argument("--request", required=True, type=Path)
    run_parser.add_argument("--output", required=True, type=Path)
    run_parser.add_argument(
        "--duration-seconds",
        type=float,
        default=None,
        help="Optional relative deadline in seconds converted to guest time.monotonic()",
    )

    args = parser.parse_args(argv)
    if args.subcommand == "probe":
        try:
            receipt = run_native_model_probe(
                expected_provider=args.provider,
                expected_model=args.model,
                user_config_root=args.user_config_root,
            )
            _private_json(args.output, receipt)
            return 0
        except BaseException as exc:
            err_payload = {
                "schemaVersion": 1,
                "status": "failed",
                "provider": args.provider,
                "requestedModel": args.model,
                "error": {"type": type(exc).__name__, "message": str(exc)[:500]},
            }
            _private_json(args.output, err_payload)
            return 2

    try:
        request = json.loads(args.request.read_text(encoding="utf-8"))
        if args.duration_seconds is not None:
            request["businessDeadlineMonotonic"] = time.monotonic() + float(args.duration_seconds)
        response = asyncio.run(execute_worker(request))
    except BaseException as exc:
        response = {
            "schemaVersion": 1,
            "status": "failed",
            "mainAnswer": {
                "status": "missing",
                "source": ANSWER_SOURCE,
                "reason": "Worker request or startup failed",
            },
            "error": {
                "type": type(exc).__name__,
                "message": str(exc)[:500],
                "reason": "invalid_request_or_startup",
            },
            "fsq": {"taskResult": None, "verification": None, "status": None},
            "actionBudget": None,
            "actionAudit": None,
            "nativeTarget": None,
            "terminationReason": "invalid_request_or_startup",
            "cleanup": {
                "closeReceipts": [],
                "vmRestored": False,
                "workerProcessExitRequiredBeforeOracle": True,
            },
        }
    _private_json(args.output, response)
    return 0 if response["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
