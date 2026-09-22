"""推理样本累计、门槛判定与不可变封存统计。"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from .models import Thresholds


@dataclass
class Metrics:
    """一座工位在某阶段窗口内的累计质量指标。"""

    samples: int = 0
    defects: int = 0
    caught_defects: int = 0
    good: int = 0
    false_rejects: int = 0
    latencies_ms: list[float] = field(default_factory=list)
    # 影子比对专用：候选与在役模型对同样本的判定差异
    shadow_pairs: int = 0
    shadow_disagreements: int = 0

    def add(
        self,
        *,
        truth: str,
        decision: str,
        latency_ms: float,
        champion_decision: str | None = None,
    ) -> None:
        if latency_ms < 0:
            raise ValueError("latency_ms 不能为负")
        self.samples += 1
        self.latencies_ms.append(float(latency_ms))
        if truth == "defect":
            self.defects += 1
            if decision == "reject":
                self.caught_defects += 1
        elif truth == "good":
            self.good += 1
            if decision == "reject":
                self.false_rejects += 1
        else:
            raise ValueError("truth 必须是 good 或 defect")
        if decision not in ("accept", "reject"):
            raise ValueError("decision 必须是 accept 或 reject")
        if champion_decision is not None:
            if champion_decision not in ("accept", "reject"):
                raise ValueError("champion_decision 必须是 accept 或 reject")
            self.shadow_pairs += 1
            if champion_decision != decision:
                self.shadow_disagreements += 1

    @property
    def defect_recall(self) -> float | None:
        return self.caught_defects / self.defects if self.defects else None

    @property
    def false_reject_rate(self) -> float | None:
        return self.false_rejects / self.good if self.good else None

    @property
    def latency_p95_ms(self) -> float | None:
        if not self.latencies_ms:
            return None
        ordered = sorted(self.latencies_ms)
        rank = math.ceil(0.95 * len(ordered))
        return ordered[rank - 1]

    def breaches(self, thresholds: Thresholds, min_samples: int) -> list[str]:
        """返回越界的安全指标名；样本不足时不判定越界。"""

        if self.samples < min_samples:
            return []
        out: list[str] = []
        recall = self.defect_recall
        if recall is None or recall < thresholds.min_defect_recall:
            out.append("defect_recall")
        frr = self.false_reject_rate
        if frr is None or frr > thresholds.max_false_reject_rate:
            out.append("false_reject_rate")
        p95 = self.latency_p95_ms
        if p95 is None or p95 > thresholds.max_latency_p95_ms:
            out.append("latency_p95_ms")
        return out

    def passes(self, thresholds: Thresholds, min_samples: int) -> bool:
        """门槛放行：样本量达标且三项安全指标全部在界内。"""

        if self.samples < min_samples:
            return False
        return not self.breaches(thresholds, min_samples)

    def snapshot(self) -> dict[str, Any]:
        return {
            "samples": self.samples,
            "defects": self.defects,
            "caught_defects": self.caught_defects,
            "good": self.good,
            "false_rejects": self.false_rejects,
            "defect_recall": self.defect_recall,
            "false_reject_rate": self.false_reject_rate,
            "latency_p95_ms": self.latency_p95_ms,
            "shadow_pairs": self.shadow_pairs,
            "shadow_disagreements": self.shadow_disagreements,
        }


@dataclass(frozen=True)
class GateRequirement:
    """进入下一阶段所需的最少样本量（影子需含足够配对）。"""

    min_samples: int
    min_shadow_pairs: int = 0

    def evaluate(self, metrics: Metrics, thresholds: Thresholds) -> list[str]:
        reasons: list[str] = []
        if metrics.samples < self.min_samples:
            reasons.append(f"样本不足：{metrics.samples}/{self.min_samples}")
        if self.min_shadow_pairs and metrics.shadow_pairs < self.min_shadow_pairs:
            reasons.append(
                f"影子配对不足：{metrics.shadow_pairs}/{self.min_shadow_pairs}"
            )
        reasons.extend(f"安全指标越界：{name}" for name in metrics.breaches(thresholds, 0))
        return reasons
