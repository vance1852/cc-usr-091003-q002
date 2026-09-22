"""换线事故重放与取证。

只读 stage_history / receipts / samples / batch_seals / rollback_evidence，
重建：受影响产品、各工位生效区间、触发回滚的样本证据、封存批次的补数。
重放不改变任何统计，且会校验工位区间互不重叠。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .domain import fmt_ts, merge_intervals
from .store import Store


@dataclass(frozen=True)
class TriggerEvidence:
    release_id: str
    station_id: str
    receipt_id: str
    triggered_at: str
    reasons: list[str]
    metrics: dict[str, Any]
    samples: list[dict[str, Any]]


class Forensics:
    def __init__(self, store: Store) -> None:
        self.store = store

    def effective_intervals(self) -> dict[str, list[dict[str, Any]]]:
        intervals = merge_intervals(self.store.intervals())  # 重叠即抛错
        result: dict[str, list[dict[str, Any]]] = {}
        for interval in intervals:
            result.setdefault(interval.station_id, []).append(
                {
                    "bundle_id": interval.bundle_id,
                    "stage": interval.stage.value,
                    "started_at": fmt_ts(interval.started_at),
                    "ended_at": fmt_ts(interval.ended_at) if interval.ended_at else None,
                    "confirmed": interval.confirmed,
                }
            )
        return result

    def affected_products(self) -> list[dict[str, Any]]:
        """据实际计入的回执与组合配方，列出受影响产品与批次。"""

        rows = self.store.query(
            """SELECT DISTINCT b.recipe_id, r.batch_id, r.station_id,
                                      r.bundle_id, r.stage, r.occurred_at
               FROM receipts r JOIN bundles b ON b.bundle_id = r.bundle_id
               ORDER BY b.recipe_id, r.occurred_at"""
        )
        products: dict[str, dict[str, Any]] = {}
        for row in rows:
            entry = products.setdefault(
                row["recipe_id"],
                {"recipe_id": row["recipe_id"], "batches": set(),
                 "stations": set(), "bundles": set()},
            )
            if row["batch_id"]:
                entry["batches"].add(row["batch_id"])
            entry["stations"].add(row["station_id"])
            entry["bundles"].add(row["bundle_id"])
        return [
            {"recipe_id": key, "batches": sorted(value["batches"]),
             "stations": sorted(value["stations"]),
             "bundles": sorted(value["bundles"])}
            for key, value in sorted(products.items())
        ]

    def rollback_triggers(self) -> list[TriggerEvidence]:
        evidence: list[TriggerEvidence] = []
        rows = self.store.query(
            "SELECT * FROM rollback_evidence ORDER BY triggered_at, id"
        )
        for row in rows:
            sample_rows = self.store.query(
                """SELECT sample_id, is_defect, model_reject, latency_ms,
                          occurred_at, received_at, batch_id
                   FROM samples WHERE receipt_id=? ORDER BY id""",
                (row["receipt_id"],),
            )
            samples = [
                {
                    "sample_id": s["sample_id"],
                    "is_defect": bool(s["is_defect"]),
                    "model_reject": bool(s["model_reject"]),
                    "false_rejected": (not s["is_defect"]) and bool(s["model_reject"]),
                    "defect_missed": s["is_defect"] and not s["model_reject"],
                    "latency_ms": s["latency_ms"],
                    "batch_id": s["batch_id"],
                    "occurred_at": s["occurred_at"],
                    "received_at": s["received_at"],
                }
                for s in sample_rows
            ]
            evidence.append(
                TriggerEvidence(
                    release_id=row["release_id"],
                    station_id=row["station_id"],
                    receipt_id=row["receipt_id"],
                    triggered_at=row["triggered_at"],
                    reasons=json.loads(row["reasons_json"]),
                    metrics=json.loads(row["metrics_json"]),
                    samples=samples,
                )
            )
        return evidence

    def sealed_batches(self) -> list[dict[str, Any]]:
        rows = self.store.query("SELECT batch_id FROM batch_seals ORDER BY sealed_at")
        result: list[dict[str, Any]] = []
        for row in rows:
            sealed = self.store.get_seal(row["batch_id"])
            assert sealed is not None
            supplements = self.store.query(
                "SELECT * FROM batch_supplements WHERE batch_id=? ORDER BY id",
                (row["batch_id"],),
            )
            result.append(
                {
                    "batch_id": row["batch_id"],
                    "sealed_at": sealed[0],
                    "stats": sealed[1],
                    "receipt_ids": list(sealed[2]),
                    "late_supplement_count": len(supplements),
                    "late_supplement_receipts": [s["receipt_id"] for s in supplements],
                }
            )
        return result

    def report(self) -> dict[str, Any]:
        return {
            "affected_products": self.affected_products(),
            "station_intervals": self.effective_intervals(),
            "rollback_triggers": [
                {
                    "release_id": item.release_id,
                    "station_id": item.station_id,
                    "receipt_id": item.receipt_id,
                    "triggered_at": item.triggered_at,
                    "reasons": item.reasons,
                    "metrics": item.metrics,
                    "samples": item.samples,
                }
                for item in self.rollback_triggers()
            ],
            "sealed_batches": self.sealed_batches(),
        }

    def render_text(self) -> str:
        report = self.report()
        lines: list[str] = []
        lines.append("== 受影响产品 ==")
        if not report["affected_products"]:
            lines.append("（无）")
        for product in report["affected_products"]:
            lines.append(
                f"- 配方 {product['recipe_id']}；批次 "
                f"{', '.join(product['batches']) or '（无批次号）'}；"
                f"工位 {', '.join(product['stations'])}；"
                f"组合 {', '.join(product['bundles'])}"
            )

        lines.append("")
        lines.append("== 各工位生效区间 ==")
        for station_id, intervals in sorted(report["station_intervals"].items()):
            lines.append(f"[{station_id}]")
            for interval in intervals:
                end = interval["ended_at"] or "（仍在生效）"
                flag = "已确认" if interval["confirmed"] else "未确认"
                lines.append(
                    f"  {interval['started_at']}  ~  {end}  "
                    f"{interval['stage']:<11} 组合 {interval['bundle_id']}  [{flag}]"
                )

        lines.append("")
        lines.append("== 触发回滚的样本证据 ==")
        if not report["rollback_triggers"]:
            lines.append("（无）")
        for trigger in report["rollback_triggers"]:
            lines.append(
                f"- 发布 {trigger['release_id']} / 工位 {trigger['station_id']} "
                f"回执 {trigger['receipt_id']} 于 {trigger['triggered_at']} 触发"
            )
            for reason in trigger["reasons"]:
                lines.append(f"    越界：{reason}")
            metrics = trigger["metrics"]
            lines.append(
                "    当时累计："
                f"n={metrics.get('n')} 召回={metrics.get('recall')} "
                f"误剔除率={metrics.get('false_reject_rate')} "
                f"p95={metrics.get('latency_p95_ms')}ms"
            )
            for sample in trigger["samples"]:
                tag = ""
                if sample["false_rejected"]:
                    tag = "  <-- 良品被误剔除"
                if sample["defect_missed"]:
                    tag = "  <-- 缺陷漏判"
                lines.append(
                    f"      样本 {sample['sample_id']}：真值缺陷={sample['is_defect']} "
                    f"模型判废={sample['model_reject']} 时延={sample['latency_ms']}ms"
                    f"（发生 {sample['occurred_at']}，接收 {sample['received_at']}）{tag}"
                )

        lines.append("")
        lines.append("== 已封存批次（统计冻结） ==")
        if not report["sealed_batches"]:
            lines.append("（无）")
        for batch in report["sealed_batches"]:
            overall = batch["stats"]["overall"]
            lines.append(
                f"- {batch['batch_id']} 封存于 {batch['sealed_at']}："
                f"样本 {overall['n']}，召回 {overall['recall']}，"
                f"误剔除率 {overall['false_reject_rate']}，"
                f"迟到补数 {batch['late_supplement_count']} 条（不改变封存统计）"
            )
            for receipt_id in batch["late_supplement_receipts"]:
                lines.append(f"    补充回执：{receipt_id}")
        return "\n".join(lines)
