"""FSQ-native macOS dispatch accounting and telemetry (zero device imports at import time).

Records every admitted macOS Harness write/read capability dispatch and captures
structured telemetry specifically on `launch_app` (`new_session` True vs False,
bundle_id vs app_path, outcome/error) without mutating native FSQ behavior.
"""

from __future__ import annotations

import inspect
import json
import math
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

MACOS_WRITE_CAPABILITIES = {
    "launch_app": "launchApp",
    "kill_app": "killApp",
    "click_on": "clickOn",
    "double_click_on": "doubleClickOn",
    "right_click_on": "rightClickOn",
    "type_text": "typeText",
    "press_key": "pressKey",
    "hover_on": "hoverOn",
    "scroll_on": "scrollOn",
    "drag_to": "dragTo",
}
MACOS_WRITE_ALIASES = {alias: name for name, alias in MACOS_WRITE_CAPABILITIES.items()}
MACOS_READ_CAPABILITIES = frozenset(
    {
        "take_screenshot",
        "screenshot",
        "ui_snapshot",
        "inspect_element",
        "sample_color",
        "inspect_with_ai",
        "assert_visible",
        "assert_not_visible",
        "assert_state",
        "assert_elements_order",
        "assert_with_ai",
    }
)
MACOS_READ_ALIASES = {
    "takeScreenshot": "take_screenshot",
    "uiSnapshot": "ui_snapshot",
    "inspectElement": "inspect_element",
    "sampleColor": "sample_color",
    "inspectWithAI": "inspect_with_ai",
    "assertVisible": "assert_visible",
    "assertNotVisible": "assert_not_visible",
    "assertState": "assert_state",
    "assertElementsOrder": "assert_elements_order",
    "assertWithAI": "assert_with_ai",
}


class NativeBoundaryError(RuntimeError):
    """A dispatch was refused before forwarding to native FSQ."""


class NativeDeadlineExceeded(NativeBoundaryError):
    pass


class NativeActionBudgetExceeded(NativeBoundaryError):
    pass


def _extract_launch_telemetry(step: Any) -> dict[str, Any]:
    params = getattr(step, "params", None)
    if isinstance(params, dict):
        raw = params
    elif hasattr(params, "model_dump"):
        raw = params.model_dump(mode="json")
    else:
        raw = {}
    return {
        "newSession": bool(raw.get("new_session", raw.get("newSession", False))),
        "hasBundleId": bool(raw.get("bundle_id") or raw.get("bundleId")),
        "bundleId": raw.get("bundle_id") or raw.get("bundleId"),
        "hasAppPath": bool(raw.get("app_path") or raw.get("appPath")),
        "hasArguments": bool(raw.get("arguments")),
    }


class NativeMacOSDispatchBudget:
    """Thread-safe before-forward admission, deadline enforcement, and launch_app audit."""

    def __init__(
        self,
        maximum: int,
        deadline: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        journal: Path | None = None,
    ) -> None:
        if type(maximum) is not int or maximum <= 0:
            raise ValueError("maxActions must be a positive integer")
        if (
            isinstance(deadline, bool)
            or not isinstance(deadline, (float, int))
            or not math.isfinite(deadline)
        ):
            raise ValueError("businessDeadlineMonotonic must be finite")
        self.maximum = maximum
        self.deadline = float(deadline)
        self.clock = clock
        self.journal = journal
        self._lock = threading.RLock()
        self._events: list[dict[str, Any]] = []
        self._launch_calls: list[dict[str, Any]] = []
        self._attempted = 0
        self._admitted = 0
        self._succeeded = 0
        self._failed = 0
        self._denied = 0
        self._next_id = 0
        self._pending: set[int] = set()
        self._deadline_exceeded = False

    def _emit(self, event: dict[str, Any]) -> None:
        record = {"sequence": len(self._events) + 1, "monotonic": self.clock(), **event}
        if self.journal is not None:
            fd = os.open(self.journal, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                data = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
                with os.fdopen(fd, "ab", closefd=False) as stream:
                    stream.write(data)
                    stream.flush()
            finally:
                os.close(fd)
        self._events.append(record)

    def check_deadline(self) -> None:
        with self._lock:
            if self.clock() >= self.deadline:
                self._deadline_exceeded = True
                raise NativeDeadlineExceeded("Business deadline reached")

    def dispatch(
        self,
        action: str,
        phase: str,
        forward: Callable[[], Any],
        *,
        step_id: str | None = None,
        step: Any = None,
    ) -> Any:
        canonical = MACOS_WRITE_ALIASES.get(action, MACOS_READ_ALIASES.get(action, action))
        write = canonical in MACOS_WRITE_CAPABILITIES
        launch_meta = _extract_launch_telemetry(step) if canonical == "launch_app" else None
        started = self.clock()
        with self._lock:
            if write:
                self._attempted += 1
            reason = None
            if self.clock() >= self.deadline:
                self._deadline_exceeded = True
                reason = "deadline"
            elif canonical in {"perform_actions", "performActions"}:
                reason = "unsupported_batch"
            if write and reason is None and self._admitted >= self.maximum:
                reason = "action_budget"
            if reason is not None:
                if write:
                    self._denied += 1
                self._emit(
                    {
                        "event": "denied",
                        "capability": canonical,
                        "phase": phase,
                        "stepId": step_id,
                        "reason": reason,
                        "countedWrite": write,
                    }
                )
                err_cls = (
                    NativeDeadlineExceeded
                    if reason == "deadline"
                    else NativeActionBudgetExceeded
                    if reason == "action_budget"
                    else NativeBoundaryError
                )
                raise err_cls(reason)
            self._next_id += 1
            ticket = self._next_id
            if write:
                self._admitted += 1
                self._pending.add(ticket)
            self._emit(
                {
                    "event": "attempted",
                    "ticket": ticket,
                    "capability": canonical,
                    "phase": phase,
                    "stepId": step_id,
                    "countedWrite": write,
                    **({"launchApp": launch_meta} if launch_meta is not None else {}),
                }
            )
        try:
            result = forward()
        except BaseException as exc:
            elapsed = round(self.clock() - started, 4)
            self._finish(
                ticket,
                canonical,
                phase,
                write,
                False,
                type(exc).__name__,
                elapsed_seconds=elapsed,
                launch_meta=launch_meta,
                failure_category=None,
            )
            raise
        elapsed = round(self.clock() - started, 4)
        status = getattr(result, "status", None)
        succeeded = status == "passed"
        failure_cat = getattr(result, "failure_category", None)
        if failure_cat is not None and hasattr(failure_cat, "value"):
            failure_cat = failure_cat.value
        self._finish(
            ticket,
            canonical,
            phase,
            write,
            succeeded,
            None if succeeded else str(status),
            elapsed_seconds=elapsed,
            launch_meta=launch_meta,
            failure_category=str(failure_cat) if failure_cat is not None else None,
        )
        return result

    def _finish(
        self,
        ticket: int,
        action: str,
        phase: str,
        write: bool,
        success: bool,
        error: str | None,
        *,
        elapsed_seconds: float,
        launch_meta: dict[str, Any] | None,
        failure_category: str | None,
    ) -> None:
        with self._lock:
            if write:
                self._pending.remove(ticket)
                if success:
                    self._succeeded += 1
                else:
                    self._failed += 1
            if launch_meta is not None:
                self._launch_calls.append(
                    {
                        "ticket": ticket,
                        **launch_meta,
                        "succeeded": success,
                        "errorType": error,
                        "failureCategory": failure_category,
                        "elapsedSeconds": elapsed_seconds,
                    }
                )
            self._emit(
                {
                    "event": "succeeded" if success else "failed",
                    "ticket": ticket,
                    "capability": action,
                    "phase": phase,
                    "countedWrite": write,
                    "errorType": error,
                    "failureCategory": failure_category,
                    "elapsedSeconds": elapsed_seconds,
                }
            )

    def receipt(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._emit(event)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "unit": "admitted_macos_harness_write_capability_dispatch",
                "writeCapabilities": list(MACOS_WRITE_CAPABILITIES),
                "maximum": self.maximum,
                "attempted": self._attempted,
                "admitted": self._admitted,
                "succeeded": self._succeeded,
                "failed": self._failed,
                "denied": self._denied,
                "inFlight": len(self._pending),
                "deadlineMonotonic": self.deadline,
                "deadlineExceeded": self._deadline_exceeded,
                "exhausted": self._admitted >= self.maximum,
                "launchAppCalls": [dict(item) for item in self._launch_calls],
                "events": [dict(event) for event in self._events],
            }


class BudgetedMacOSHarness:
    """Explicit complete HarnessInterface delegate for native MacOSHarness."""

    def __init__(self, native: Any, budget: NativeMacOSDispatchBudget) -> None:
        self.native = native
        self.dispatch_budget = budget

    @property
    def visual_ai_eligible(self) -> bool | None:
        return getattr(self.native, "visual_ai_eligible", None)

    @property
    def available_scoped_visual_tools(self) -> tuple[str, ...] | frozenset[str]:
        return getattr(self.native, "available_scoped_visual_tools", ())

    def capture_scope(self, callback: Any) -> Any:
        return self.native.capture_scope(callback)

    def get_context(self) -> Any:
        return self.native.get_context()

    def action_space(self) -> Any:
        return self.native.action_space()

    def before_action(self, step: Any, context: Any) -> None:
        return self.native.before_action(step, context)

    def invoke_action(self, step: Any, context: Any) -> Any:
        return self.dispatch_budget.dispatch(
            step.action_name,
            step.kind,
            lambda: self.native.invoke_action(step, context),
            step_id=step.step_id,
            step=step,
        )

    def after_action(self, step: Any, context: Any, action_result: Any) -> None:
        return self.native.after_action(step, context, action_result)

    def capture_artifact(
        self, kind: str, reason: str, context: Any, step_id: str, phase: str
    ) -> Any:
        return self.native.capture_artifact(kind, reason, context, step_id, phase)

    def classify_error(self, error: BaseException, phase: str, step: Any) -> Any:
        return self.native.classify_error(error, phase, step)

    def close(self) -> None:
        self.dispatch_budget.receipt(
            {"event": "close_started", "resource": "macos_harness", "vmRestored": False}
        )
        try:
            self.native.close()
        except BaseException as exc:
            self.dispatch_budget.receipt(
                {
                    "event": "close_failed",
                    "resource": "macos_harness",
                    "errorType": type(exc).__name__,
                    "vmRestored": False,
                }
            )
            raise
        self.dispatch_budget.receipt(
            {"event": "close_succeeded", "resource": "macos_harness", "vmRestored": False}
        )


def _run_visual_eligibility_parameter(create_harness: Callable[..., Any]) -> str | None:
    """Find an explicitly declared boolean visual eligibility keyword, never **kwargs."""
    matches = []
    for parameter in inspect.signature(create_harness).parameters.values():
        name = parameter.name
        if parameter.kind not in (
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ) or "visual" not in name.split("_") or not {"eligible", "eligibility"}.intersection(name.split("_")):
            continue
        annotation = parameter.annotation
        if (
            annotation is bool
            or annotation == bool | None
            or isinstance(annotation, str) and annotation.replace(" ", "") in {"bool", "bool|None", "None|bool"}
            or annotation is inspect.Parameter.empty and type(parameter.default) is bool
        ):
            matches.append(name)
    if len(matches) > 1:
        raise NativeBoundaryError("Ambiguous explicit native visual eligibility parameters")
    return matches[0] if matches else None


def build_native_macos_harness_factory(
    settings: Any, budget: NativeMacOSDispatchBudget
) -> Callable[[str], Any]:
    """Construct native MacOSHarness with controlled benchmark visual assertion policy."""
    from fsq_agent.ai_services import build_ai_assertion_evaluator
    from fsq_agent.core import ArtifactStore, HarnessFactory

    def factory(run_id: str) -> Any:
        budget.check_deadline()
        if not run_id or run_id in {".", ".."} or any(c in run_id for c in "/\\:\x00"):
            raise ValueError("Invalid native run ID")
        create_harness = HarnessFactory().create_harness
        visual_kwargs: dict[str, Any] = {}
        visual_policy = getattr(settings.harness.macos, "visual_assertion_policy", None)
        evaluator = build_ai_assertion_evaluator(settings)
        if (
            visual_policy is not None
            and visual_policy.allow_provider_upload is True
            and visual_policy.frame_sensitivity == "non_sensitive"
            and visual_policy.provider_available is not False
            and callable(getattr(evaluator, "evaluate", None))
            and callable(getattr(evaluator, "inspect", None))
        ):
            parameters = inspect.signature(create_harness).parameters
            resolver = parameters.get("visual_assertion_policy_resolver")
            accepts_resolver = (
                resolver is not None
                and resolver.kind
                in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
            ) or (
                resolver is None
                and any(
                    param.kind == inspect.Parameter.VAR_KEYWORD
                    for param in parameters.values()
                )
            )
            if not accepts_resolver:
                raise NativeBoundaryError(
                    "Native FSQ visual policy requires visual_assertion_policy_resolver"
                )
            visual_kwargs["visual_assertion_policy_resolver"] = (
                lambda _context, _sequence: visual_policy
            )
            eligibility = _run_visual_eligibility_parameter(create_harness)
            if eligibility is not None:
                visual_kwargs[eligibility] = True
        store = ArtifactStore(
            settings.output.runs_dir / run_id,
            secret_values=tuple(settings.runtime_secrets.private_values().values()),
        )
        try:
            native = create_harness(
                platform="macos",
                harness_settings=settings.harness,
                artifact_store=store,
                ai_assertion_evaluator=evaluator,
                runtime_secret_settings=settings.runtime_secrets,
                bundle_id=settings.harness.macos.bundle_id,
                **visual_kwargs,
            )
        except BaseException as exc:
            budget.receipt(
                {
                    "event": "construction_failed",
                    "errorType": type(exc).__name__,
                    "cleanupOwner": "native_harness_factory",
                }
            )
            raise
        harness = BudgetedMacOSHarness(native, budget)
        try:
            for schema in harness.action_space():
                method = schema.driver_method
                if (
                    schema.metadata.get("executor_kind") == "driver"
                    and method not in MACOS_WRITE_CAPABILITIES
                    and method not in MACOS_READ_CAPABILITIES
                ):
                    raise NativeBoundaryError(
                        f"Unsupported native macOS driver capability: {method}"
                    )
        except BaseException:
            try:
                harness.close()
            except BaseException:
                pass
            raise
        return harness

    return factory
