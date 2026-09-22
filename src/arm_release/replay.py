"""换线事故重放。

质量人员从事件流（而非当前状态）还原：
- 受影响产品（配方）
- 每座工位每个发布组合/阶段的生效区间 [start, end)
- 冻结与回滚事件，以及触发回滚的样本回执证据

重放只读、确定性，不依赖系统时间。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .models import parse_ts
from .store import Store

TERMINAL_ACTIONS = {"station_active", "rolled_back"}
TRANSITION_ACTIONS = {
    "shadow_started": "shadow",
    "canary_started": "canary",
    "rollout_started": "rollout",
    "station_active": "active",
}


@dataclass
class Interval:
    station_id: str
    bundle_id: str
    phase: str
    start: str
    end: str | None = None
    recipe: str | None = None
    recipe_version: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "station_id": self.station_id,
            "bundle_id": self.bundle_id,
            "phase": self.phase,
            "start": self.start,
            "end": self.end,
            "recipe": self.recipe,
            "recipe_version": self.recipe_version,
            "detail": self.detail,
        }


@dataclass
class RollbackEvidence:
    station_id: str
    bundle_id: str
    at: str
    from_phase: str
    reverted_to: str | None
    trigger_receipt_id: str | None
    breached: list[str]
    metrics: dict[str, Any]
    thresholds: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "station_id": self.station_id,
            "bundle_id": self.bundle_id,
            "at": self.at,
            "from_phase": self.from_phase,
            "reverted_to": self.reverted_to,
            "trigger_receipt_id": self.trigger_receipt_id,
            "breached": self.breached,
            "metrics": self.metrics,
            "thresholds": self.thresholds,
        }


def _bundle_meta(store: Store, bundle_id: str) -> tuple[str | None, str | None]:
    row = store.get_bundle(bundle_id)
    if row is None:
        return None, None
    return row["recipe"], row["recipe_version"]


def replay(store: Store) -> dict[str, Any]:
    """对持久化事件流做确定性重放。"""

    events = sorted(
        store.list_stage_events(),
        key=lambda e: (parse_ts(e["at_time"]), e["id"]),
    )

    intervals: list[Interval] = []
    rollbacks: list[RollbackEvidence] = []
    freezes: list[dict[str, Any]] = []
    affected: dict[str, set[str]] = {}

    # 每工位当前开启的区间
    open_interval: dict[str, Interval] = {}

    for e in events:
        t = parse_ts(e["at_time"])
        detail = json.loads(e["detail_json"])
        station = e["station_id"]
        bundle_id = e["bundle_id"]

        if e["action"] == "rollout_frozen":
            freezes.append(
                {
                    "bundle_id": bundle_id,
                    "at": e["at_time"],
                    "actor": e["actor"],
                    "reason": detail,
                }
            )
            continue

        if e["action"] == "bundle_approved":
            continue

        if e["action"] == "stable_established":
            current = open_interval.pop(station, None)
            if current is not None:
                current.end = e["at_time"]
                intervals.append(current)
            iv = Interval(
                station_id=station,
                bundle_id=bundle_id,
                phase="stable",
                start=e["at_time"],
                recipe=_bundle_meta(store, bundle_id)[0],
                recipe_version=_bundle_meta(store, bundle_id)[1],
            )
            # stable 区间保持开启，直到下一个候选事件
            open_interval[station] = iv
            continue

        if e["action"] == "rolled_back":
            current = open_interval.pop(station, None)
            if current is not None:
                current.end = e["at_time"]
                intervals.append(current)
            # 找到触发该组合冻结的证据
            freeze_reason: dict[str, Any] = {}
            for f in freezes:
                if f["bundle_id"] == bundle_id:
                    freeze_reason = f["reason"]
            rollbacks.append(
                RollbackEvidence(
                    station_id=station,
                    bundle_id=bundle_id,
                    at=e["at_time"],
                    from_phase=detail.get("from_phase"),
                    reverted_to=detail.get("reverted_to"),
                    trigger_receipt_id=freeze_reason.get("evidence_receipt_id"),
                    breached=freeze_reason.get("breached", []),
                    metrics=freeze_reason.get("metrics", {}),
                    thresholds=freeze_reason.get("thresholds", {}),
                )
            )
            reverted = detail.get("reverted_to")
            if reverted:
                iv = Interval(
                    station_id=station,
                    bundle_id=reverted,
                    phase="stable",
                    start=e["at_time"],
                )
                recipe, ver = _bundle_meta(store, reverted)
                iv.recipe = recipe
                iv.recipe_version = ver
                open_interval[station] = iv
            continue

        phase = TRANSITION_ACTIONS.get(e["action"])
        if phase is None:
            continue

        current = open_interval.pop(station, None)
        if current is not None:
            current.end = e["at_time"]
            intervals.append(current)
        recipe, ver = _bundle_meta(store, bundle_id)
        iv = Interval(
            station_id=station,
            bundle_id=bundle_id,
            phase=phase,
            start=e["at_time"],
            recipe=recipe,
            recipe_version=ver,
            detail={"gate_metrics": detail.get("gate_metrics")} if detail.get("gate_metrics") else {},
        )
        if recipe:
            affected.setdefault(recipe, set()).add(ver or "")
        if e["action"] == "station_active":
            iv.end = e["at_time"]
            intervals.append(iv)
            # 紧接着开启新的在役 stable 区间
            stable_iv = Interval(
                station_id=station,
                bundle_id=bundle_id,
                phase="stable",
                start=e["at_time"],
                recipe=recipe,
                recipe_version=ver,
            )
            open_interval[station] = stable_iv
        else:
            open_interval[station] = iv

    # 闭合仍开启的区间（end=None 表示重放时刻仍生效）
    for iv in open_interval.values():
        intervals.append(iv)

    intervals.sort(key=lambda x: (x.station_id, parse_ts(x.start)))

    # 受影响产品：凡是候选/回滚区间覆盖到的配方
    for iv in intervals:
        if iv.recipe and iv.phase != "stable":
            affected.setdefault(iv.recipe, set()).add(iv.recipe_version or "")
    for rb in rollbacks:
        recipe, ver = _bundle_meta(store, rb.bundle_id)
        if recipe:
            affected.setdefault(recipe, set()).add(ver or "")

    return {
        "affected_products": [
            {"recipe": recipe, "recipe_versions": sorted(versions)}
            for recipe, versions in sorted(affected.items())
        ],
        "intervals": [iv.to_dict() for iv in intervals],
        "freezes": freezes,
        "rollbacks": [rb.to_dict() for rb in rollbacks],
    }


def evidence_samples(store: Store, report: dict[str, Any]) -> list[dict[str, Any]]:
    """列出触发冻结/回滚的样本回执（按唯一回执去重），并标明冻结波及工位。"""

    by_receipt: dict[str, dict[str, Any]] = {}
    for rb in report["rollbacks"]:
        rid = rb.get("trigger_receipt_id")
        if not rid or rid in by_receipt:
            continue
        row = store.get_receipt(rid)
        if row is None:
            continue
        by_receipt[rid] = {
            "receipt_id": rid,
            "station_id": row["station_id"],
            "bundle_id": rb["bundle_id"],
            "occurred_at": row["occurred_at"],
            "received_at": row["received_at"],
            "truth": row["truth"],
            "decision": row["decision"],
            "latency_ms": row["latency_ms"],
            "counted_phase": row["counted_phase"],
            "breached": rb["breached"],
            "rollback_propagated_to": sorted(
                other["station_id"]
                for other in report["rollbacks"]
                if other.get("trigger_receipt_id") == rid
            ),
        }
    return list(by_receipt.values())
