"""Frozen wheel identity, SHA256 verification, and suite task catalog."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Any, Literal

SubsetName = Literal["macarena", "macosworld", "osworld"]

FROZEN_PROVIDER = "github_copilot"
FROZEN_MODEL = "gpt-6.1-sol"
INITIAL_BUNDLE_ID = "com.apple.finder"
AUTO_FRONTMOST_BUNDLE_ID = "auto"

APPIUM_CONNECT_WHEEL_DEFAULT = Path(
    "/Users/qunmi/Documents/FSQ_LAB/appium-connect-agent/dist/appium_connect_agent-0.1.2-py3-none-any.whl"
)
APPIUM_CONNECT_WHEEL_SHA256 = (
    "a6ac14573157138ff9140995f28081abf14114e3af794388f92cb9ab1692ec30"
)
APPIUM_CONNECT_SOURCE_COMMIT = "65363e7eae6310acf365dee652da7592196b6bb2"

FSQ_AGENT_WHEEL_DEFAULT = Path(
    "/Users/qunmi/Documents/FSQ_LAB/FSQ/dist/fsq_agent-0.3.8-py3-none-any.whl"
)
FSQ_AGENT_WHEEL_SHA256 = (
    "2927a13d5bca6e7e836cf0f7c9761840aaa17221bc4df7b3413a3ab2de69cbb7"
)
FSQ_AGENT_SOURCE_COMMIT = "761342030e545b1447420b282d35c2410d40e07d"
SUBSET_TO_BASE_VM: dict[SubsetName, str] = {
    "macarena": "macarena",
    "macosworld": "osworld",
    "osworld": "osworld",
}

EXPECTED_SUBSET_COUNTS: dict[SubsetName, int] = {
    "macarena": 49,
    "macosworld": 151,
    "osworld": 221,
}


@dataclasses.dataclass(frozen=True)
class FrozenWheelSpec:
    package_name: str
    version: str
    path: Path
    expected_sha256: str
    source_commit: str | None = None


@dataclasses.dataclass(frozen=True)
class TaskRecord:
    subset: SubsetName
    category: str
    task_id: str
    base_vm: str
    json_path: Path
    instruction: str
    config: dict[str, Any]
    sha256: str


def file_sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Frozen artifact must be a regular non-symlink file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def default_frozen_wheels(
    *,
    appium_connect_wheel: Path | None = None,
    fsq_agent_wheel: Path | None = None,
) -> tuple[FrozenWheelSpec, FrozenWheelSpec]:
    return (
        FrozenWheelSpec(
            package_name="appium-connect-agent",
            version="0.1.2",
            path=(appium_connect_wheel or APPIUM_CONNECT_WHEEL_DEFAULT).expanduser().resolve(),
            expected_sha256=APPIUM_CONNECT_WHEEL_SHA256,
            source_commit=APPIUM_CONNECT_SOURCE_COMMIT,
        ),
        FrozenWheelSpec(
            package_name="fsq-agent",
            version="0.3.8",
            path=(fsq_agent_wheel or FSQ_AGENT_WHEEL_DEFAULT).expanduser().resolve(),
            expected_sha256=FSQ_AGENT_WHEEL_SHA256,
            source_commit=FSQ_AGENT_SOURCE_COMMIT,
        ),
    )


def verify_frozen_wheels(
    specs: tuple[FrozenWheelSpec, ...] | None = None,
) -> dict[str, Any]:
    wheel_specs = specs if specs is not None else default_frozen_wheels()
    verified: list[dict[str, Any]] = []
    for spec in wheel_specs:
        if spec.path.suffix != ".whl":
            raise ValueError(f"Frozen artifact is not a wheel (.whl): {spec.path}")
        observed = file_sha256(spec.path)
        if observed != spec.expected_sha256:
            raise ValueError(
                f"SHA256 mismatch for {spec.package_name} ({spec.path}): "
                f"expected {spec.expected_sha256}, observed {observed}"
            )
        verified.append(
            {
                "packageName": spec.package_name,
                "version": spec.version,
                "path": str(spec.path),
                "sizeBytes": spec.path.stat().st_size,
                "sha256": observed,
                "sourceCommit": spec.source_commit,
                "editable": False,
            }
        )
    return {
        "schemaVersion": 1,
        "provider": FROZEN_PROVIDER,
        "model": FROZEN_MODEL,
        "initialBundleId": AUTO_FRONTMOST_BUNDLE_ID,
        "wheels": verified,
    }


def discover_tasks(
    macarena_repo: Path,
    *,
    subsets: tuple[SubsetName, ...] = ("macarena", "macosworld", "osworld"),
) -> list[TaskRecord]:
    examples_root = (macarena_repo / "evaluation_examples").resolve()
    if not examples_root.is_dir():
        raise FileNotFoundError(f"MacArena evaluation_examples not found: {examples_root}")

    records: list[TaskRecord] = []
    for subset in subsets:
        if subset not in SUBSET_TO_BASE_VM:
            raise ValueError(f"Unsupported subset: {subset}")
        subset_dir = examples_root / subset
        if not subset_dir.is_dir():
            raise FileNotFoundError(f"Subset directory missing: {subset_dir}")
        paths = sorted(subset_dir.rglob("*.json"))
        for json_path in paths:
            raw = json_path.read_bytes()
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError(f"Task JSON must be an object: {json_path}")
            task_id = str(payload.get("id") or json_path.stem)
            instruction = payload.get("instruction")
            if not isinstance(instruction, str) or not instruction.strip():
                raise ValueError(f"Task JSON missing non-empty instruction: {json_path}")
            rel_parts = json_path.relative_to(subset_dir).parts
            category = rel_parts[0] if len(rel_parts) > 1 else "uncategorized"
            records.append(
                TaskRecord(
                    subset=subset,
                    category=category,
                    task_id=task_id,
                    base_vm=SUBSET_TO_BASE_VM[subset],
                    json_path=json_path,
                    instruction=instruction,
                    config=payload,
                    sha256=hashlib.sha256(raw).hexdigest(),
                )
            )
    return records


def select_smoke_6_tasks(macarena_repo: Path) -> list[TaskRecord]:
    """Select 6 deterministic live smoke tasks across all 3 subsets (2 + 2 + 2).

    Includes native app launching/switching tasks as well as Finder/file tasks
    so `launch_app(new_session=False)` and dual-VM concurrency (`--workers 2`)
    are exercised end-to-end before authorizing the full 421-task run.
    """
    all_tasks = discover_tasks(macarena_repo)
    by_subset: dict[SubsetName, list[TaskRecord]] = {
        "macarena": [],
        "macosworld": [],
        "osworld": [],
    }
    for rec in all_tasks:
        by_subset[rec.subset].append(rec)

    selected: list[TaskRecord] = []
    # 1) macarena: 1 third-party/system app task (Notes or TextEdit) + 1 file_management task
    macarena_app = next(
        (
            t
            for t in by_subset["macarena"]
            if t.config.get("related_apps") in (["Notes"], ["TextEdit"], ["Reminders"])
            and not t.config.get("pre_upload_files")
        ),
        by_subset["macarena"][0],
    )
    macarena_file = next(
        (
            t
            for t in by_subset["macarena"]
            if t.category == "file_management" and t.task_id != macarena_app.task_id
        ),
        by_subset["macarena"][1],
    )
    selected.extend([macarena_app, macarena_file])

    # 2) macosworld: 1 file_management + 1 sys_apps
    mw_file = next(
        (t for t in by_subset["macosworld"] if t.category == "file_management"),
        by_subset["macosworld"][0],
    )
    mw_app = next(
        (
            t
            for t in by_subset["macosworld"]
            if t.category == "sys_apps" and t.task_id != mw_file.task_id
        ),
        by_subset["macosworld"][1],
    )
    selected.extend([mw_file, mw_app])

    # 3) osworld: 1 os task + 1 vs_code/chrome non-proxy feasible task
    os_basic = next(
        (
            t
            for t in by_subset["osworld"]
            if t.category == "os"
            and not t.config.get("proxy")
            and (t.config.get("evaluator") or {}).get("func") != "infeasible"
        ),
        by_subset["osworld"][0],
    )
    os_app = next(
        (
            t
            for t in by_subset["osworld"]
            if t.category in ("vs_code", "chrome")
            and not t.config.get("proxy")
            and (t.config.get("evaluator") or {}).get("func") != "infeasible"
            and t.task_id != os_basic.task_id
        ),
        by_subset["osworld"][1],
    )
    selected.extend([os_basic, os_app])
    return selected


def load_task_ids_from_manifest(manifest_path: Path) -> list[str]:
    """Load ordered `taskId` strings from a curated regression manifest JSON file."""
    payload = json.loads(manifest_path.expanduser().resolve().read_text(encoding="utf-8"))
    if isinstance(payload, list):
        entries = payload
    elif isinstance(payload, dict) and isinstance(payload.get("tasks"), list):
        entries = payload["tasks"]
    else:
        raise ValueError(f"Unsupported task manifest format in {manifest_path}")
    task_ids: list[str] = []
    for item in entries:
        if isinstance(item, str) and item.strip():
            task_ids.append(item.strip())
        elif isinstance(item, dict) and isinstance(item.get("taskId"), str) and item["taskId"].strip():
            task_ids.append(item["taskId"].strip())
        else:
            raise ValueError(f"Invalid task entry in {manifest_path}: {item!r}")
    return task_ids
