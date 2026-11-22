"""CLI entrypoints for `fsq-macarena-eval`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .manifest import (
    AUTO_FRONTMOST_BUNDLE_ID,
    EXPECTED_SUBSET_COUNTS,
    discover_tasks,
    load_task_ids_from_manifest,
    select_smoke_6_tasks,
    verify_frozen_wheels,
)
from .provision import bake_both_golden_vms_in_place, provision_golden_vm
from .runner import run_campaign
from .utm_supervisor import UTM_DOCUMENTS_DIR, DualSlotUTMSupervisor


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fsq-macarena-eval",
        description="Official MacArena benchmark harness for native FSQ macOS capability evaluation.",
    )
    parser.add_argument(
        "--macarena-repo",
        type=Path,
        default=Path("MacArena"),
        help="Path to cloned MacPaw/MacArena repository",
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path("artifacts/state"),
        help="State directory for SSH keys, locks, and Golden VM readiness receipts",
    )
    parser.add_argument(
        "--utm-documents-dir",
        type=Path,
        default=UTM_DOCUMENTS_DIR,
        help="Directory containing the base .utm bundles to clone",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("verify-freeze", help="Verify SHA256 of frozen wheels and suite counts")

    prov = sub.add_parser("provision-vm", help="Import and provision a Golden Base VM")
    prov.add_argument("--base-vm", choices=["macarena", "osworld"], required=True)
    prov.add_argument("--source-bundle", type=Path, required=True)
    prov.add_argument("--xcode-donor-bundle", type=Path, default=None)

    bake = sub.add_parser(
        "bake-golden-vms",
        help="One-shot upgrade of both Golden VMs (Aqua TCC + iWork/LibreOffice/Obsidian/Klee + frozen wheels)",
    )
    bake.add_argument(
        "--targets",
        nargs="+",
        choices=["osworld", "macarena"],
        default=["osworld", "macarena"],
        help="Golden Base VMs to upgrade in order (`osworld` first so its iWork/LibreOffice can sync into `macarena`)",
    )
    bake.add_argument("--appium-wheel", type=Path, default=None)
    bake.add_argument("--fsq-wheel", type=Path, default=None)

    smoke = sub.add_parser(
        "smoke-6",
        help="Run the 6-task cross-subset live Smoke Gate (2 macarena + 2 macosworld + 2 osworld)",
    )
    smoke.add_argument("--workers", type=int, choices=[1, 2], default=2)
    smoke.add_argument("--campaign-dir", type=Path, default=Path("runs/smoke-6"))
    smoke.add_argument("--max-actions", type=int, default=50)
    smoke.add_argument("--max-turns", type=int, default=100)
    smoke.add_argument("--episode-timeout", type=float, default=900.0)

    smoke.add_argument(
        "--oracle-mode",
        choices=["strict-upstream", "patched-oracle"],
        default="strict-upstream",
    )
    smoke.add_argument("--initial-bundle-id", default=AUTO_FRONTMOST_BUNDLE_ID)
    smoke.add_argument(
        "--allow-visual-provider-upload",
        action="store_true",
        help="Authorize visual provider upload for this run's non-sensitive fixture frames",
    )
    camp = sub.add_parser("run", help="Run evaluation campaign on selected subsets or task IDs")
    camp.add_argument(
        "--subset",
        "--subsets",
        dest="subsets",
        nargs="+",
        choices=["macarena", "macosworld", "osworld"],
        default=["macarena", "macosworld"],
        help="One or more subsets to run (defaults to `macarena` + `macosworld`)",
    )
    camp.add_argument("--task-ids", nargs="*", default=None)
    camp.add_argument(
        "--task-manifest",
        type=Path,
        default=None,
        help="Optional JSON manifest file containing ordered `taskId` entries (e.g. manifests/golden_regression_36.json)",
    )
    camp.add_argument("--workers", type=int, choices=[1, 2], default=2)
    camp.add_argument("--campaign-dir", type=Path, required=True)
    camp.add_argument("--max-actions", type=int, default=60)
    camp.add_argument("--max-turns", type=int, default=100)
    camp.add_argument("--episode-timeout", type=float, default=900.0)
    camp.add_argument("--no-resume", action="store_true")
    camp.add_argument(
        "--oracle-mode",
        choices=["strict-upstream", "patched-oracle"],
        default="strict-upstream",
    )
    camp.add_argument("--initial-bundle-id", default=AUTO_FRONTMOST_BUNDLE_ID)
    camp.add_argument(
        "--allow-visual-provider-upload",
        action="store_true",
        help="Authorize visual provider upload for this run's non-sensitive fixture frames",
    )

    args = parser.parse_args(argv)
    repo = args.macarena_repo.expanduser().resolve()

    if args.cmd == "verify-freeze":
        wheels = verify_frozen_wheels()
        tasks = discover_tasks(repo)
        counts: dict[str, int] = {}
        for t in tasks:
            counts[t.subset] = counts.get(t.subset, 0) + 1
        if counts != EXPECTED_SUBSET_COUNTS:
            raise ValueError(f"Subset count mismatch: {counts} != {EXPECTED_SUBSET_COUNTS}")
        smoke_tasks = select_smoke_6_tasks(repo)
        out = {
            "frozenWheels": wheels,
            "subsetCounts": counts,
            "totalTasks": len(tasks),
            "smoke6Tasks": [
                {
                    "subset": t.subset,
                    "category": t.category,
                    "taskId": t.task_id,
                    "baseVm": t.base_vm,
                    "relatedApps": t.config.get("related_apps", []),
                    "instruction": t.instruction,
                }
                for t in smoke_tasks
            ],
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0

    supervisor = DualSlotUTMSupervisor(
        state_dir=args.state_dir, utm_documents_dir=args.utm_documents_dir
    )

    if args.cmd == "provision-vm":
        vm_name = "macOS" if args.base_vm == "macarena" else "osworld"
        # Note: we name Golden VMs `macarena` and `osworld` in UTM Documents to match SUBSET_TO_BASE_VM
        vm_name = args.base_vm
        receipt = provision_golden_vm(
            base_vm_name=vm_name,
            source_bundle=args.source_bundle,
            macarena_repo=repo,
            project_root=Path.cwd(),
            supervisor=supervisor,
            xcode_donor_bundle=args.xcode_donor_bundle,
        )
        print(json.dumps(receipt, indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "bake-golden-vms":
        receipt = bake_both_golden_vms_in_place(
            targets=tuple(args.targets),
            macarena_repo=repo,
            project_root=Path.cwd(),
            supervisor=supervisor,
            appium_connect_wheel=args.appium_wheel,
            fsq_agent_wheel=args.fsq_wheel,
        )
        print(json.dumps(receipt, indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "smoke-6":
        tasks = select_smoke_6_tasks(repo)
        summary = run_campaign(
            tasks=tasks,
            supervisor=supervisor,
            macarena_repo=repo,
            campaign_dir=args.campaign_dir,
            workers=args.workers,
            max_actions=args.max_actions,
            max_turns=args.max_turns,
            episode_timeout_seconds=args.episode_timeout,
            initial_bundle_id=args.initial_bundle_id,
            oracle_mode=args.oracle_mode,
            visual_provider_upload_allowed=args.allow_visual_provider_upload,
        )
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "run":
        tasks = discover_tasks(repo, subsets=tuple(args.subsets))
        wanted_ordered: list[str] = []
        if args.task_manifest is not None:
            wanted_ordered.extend(load_task_ids_from_manifest(args.task_manifest))
        if args.task_ids:
            wanted_ordered.extend(args.task_ids)
        if wanted_ordered:
            by_id = {t.task_id: t for t in tasks}
            missing = [tid for tid in wanted_ordered if tid not in by_id]
            if missing:
                raise ValueError(
                    f"Requested task IDs not found in subsets {args.subsets}: {missing}"
                )
            seen: set[str] = set()
            ordered_tasks: list = []
            for tid in wanted_ordered:
                if tid not in seen:
                    seen.add(tid)
                    ordered_tasks.append(by_id[tid])
            tasks = ordered_tasks
        summary = run_campaign(
            tasks=tasks,
            supervisor=supervisor,
            macarena_repo=repo,
            campaign_dir=args.campaign_dir,
            workers=args.workers,
            max_actions=args.max_actions,
            max_turns=args.max_turns,
            episode_timeout_seconds=args.episode_timeout,
            initial_bundle_id=args.initial_bundle_id,
            oracle_mode=args.oracle_mode,
            resume=not args.no_resume,
            visual_provider_upload_allowed=args.allow_visual_provider_upload,
        )
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
