"""换线放行的领域模型与纯逻辑。

本模块不接触数据库与系统时钟：所有时间由调用方显式传入，
持久化与服务层在 :mod:`arm_release.store` 与 :mod:`arm_release.app`。
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum


class DomainError(ValueError):
    """领域规则被违反。"""


def parse_ts(value: str) -> datetime:
    """解析带时区的时间戳并归一化为 UTC。"""

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DomainError(f"不是有效时间：{value}") from exc
    if parsed.tzinfo is None:
        raise DomainError(f"时间缺少时区：{value}")
    return parsed.astimezone(timezone.utc)


def fmt_ts(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# --- 资产与门槛 ----------------------------------------------------------


class Stage(str, Enum):
    SHADOW = "shadow"        # 影子比对，不发给机械臂
    CANARY = "canary"        # 限量试运行
    ACTIVE = "active"        # 扩围（全量）
    ROLLED_BACK = "rolled_back"


# 阶段递进顺序：影子 -> 单站限量 -> 扩围。
STAGE_ORDER = (Stage.SHADOW, Stage.CANARY, Stage.ACTIVE)


@dataclass(frozen=True)
class Thresholds:
    """某产品配方的安全门槛。"""

    recipe_id: str
    min_recall: float            # 缺陷召回下限
    max_false_reject_rate: float # 误剔除率上限
    max_latency_ms: float        # 推理时延（p95）上限
    min_decision_samples: int    # 判定扩围所需最少样本
    canary_cap: int              # 限量试运行的件数上限

    def validate(self) -> None:
        if not 0.0 <= self.min_recall <= 1.0:
            raise DomainError("min_recall 必须落在 [0,1]")
        if not 0.0 <= self.max_false_reject_rate <= 1.0:
            raise DomainError("max_false_reject_rate 必须落在 [0,1]")
        if self.max_latency_ms <= 0:
            raise DomainError("max_latency_ms 必须为正")
        if self.min_decision_samples <= 0:
            raise DomainError("min_decision_samples 必须为正")
        if self.canary_cap < self.min_decision_samples:
            raise DomainError("canary_cap 不得小于 min_decision_samples")


@dataclass(frozen=True)
class ModelRecord:
    model_id: str
    digest: str
    signature: bytes
    key_id: str

    def signing_message(self) -> bytes:
        return canonical_json(
            ["model@v1", self.model_id, self.digest]
        )


@dataclass(frozen=True)
class CalibrationRecord:
    calib_id: str
    station_id: str
    digest: str
    signature: bytes | None
    key_id: str | None


@dataclass(frozen=True)
class RecipeRecord:
    recipe_id: str
    digest: str
    thresholds: Thresholds


# --- 发布组合（模型 + 标定 + 配方，不可拆分） -----------------------------


@dataclass(frozen=True)
class Bundle:
    bundle_id: str
    model_id: str
    recipe_id: str
    calibs: dict[str, str]  # station_id -> calib_id
    created_by: str
    created_at: datetime

    def calib_for(self, station_id: str) -> str:
        try:
            return self.calibs[station_id]
        except KeyError:
            raise DomainError(f"组合 {self.bundle_id} 未绑定工位 {station_id} 的标定")


def bundle_fingerprint(
    model: ModelRecord,
    recipe: RecipeRecord,
    calibs: dict[str, CalibrationRecord],
) -> str:
    """组合内全部构件的总指纹，任一件被替换即变化。"""

    payload = canonical_json(
        [
            "bundle@v1",
            model.model_id,
            model.digest,
            recipe.recipe_id,
            recipe.digest,
            sorted((station, calib.digest) for station, calib in calibs.items()),
        ]
    )
    return "sha256:" + hashlib.sha256(payload).hexdigest()


# --- 推理样本与指标 ------------------------------------------------------


@dataclass(frozen=True)
class SampleInput:
    sample_id: str
    is_defect: bool        # 真值：是否缺陷件
    model_reject: bool     # 模型是否判废
    latency_ms: float


@dataclass(frozen=True)
class Sample:
    station_id: str
    bundle_id: str
    batch_id: str | None
    receipt_id: str
    sample_id: str
    is_defect: bool
    model_reject: bool
    latency_ms: float
    occurred_at: datetime
    received_at: datetime

    @property
    def caught(self) -> bool:
        return self.is_defect and self.model_reject

    @property
    def false_rejected(self) -> bool:
        return (not self.is_defect) and self.model_reject


@dataclass(frozen=True)
class Metrics:
    n: int
    defects: int
    caught: int
    good: int
    false_rejected: int
    recall: float | None
    false_reject_rate: float | None
    latency_p95_ms: float | None

    def to_dict(self) -> dict[str, object]:
        return {
            "n": self.n,
            "defects": self.defects,
            "caught": self.caught,
            "good": self.good,
            "false_rejected": self.false_rejected,
            "recall": self.recall,
            "false_reject_rate": self.false_reject_rate,
            "latency_p95_ms": self.latency_p95_ms,
        }


def evaluate(samples: list[Sample]) -> Metrics:
    n = len(samples)
    defects = sum(s.is_defect for s in samples)
    caught = sum(s.caught for s in samples)
    good = n - defects
    false_rejected = sum(s.false_rejected for s in samples)
    recall = caught / defects if defects else None
    frr = false_rejected / good if good else None
    if n:
        ordered = sorted(s.latency_ms for s in samples)
        rank = max(1, -(-(95 * n) // 100))  # 最近秩 ceil(0.95n)
        p95 = ordered[rank - 1]
    else:
        p95 = None
    return Metrics(n, defects, caught, good, false_rejected, recall, frr, p95)


@dataclass(frozen=True)
class GateVerdict:
    passed: bool
    reasons: list[str]
    metrics: dict[str, object]

    def raise_if_failed(self) -> None:
        if not self.passed:
            raise DomainError("安全门槛未通过：" + "；".join(self.reasons))


def evaluate_gate(
    samples: list[Sample],
    thresholds: Thresholds,
    *,
    require_decision_volume: bool = True,
) -> GateVerdict:
    metrics = evaluate(samples)
    reasons: list[str] = []
    if require_decision_volume and metrics.n < thresholds.min_decision_samples:
        reasons.append(
            f"样本量 {metrics.n} 少于判定下限 {thresholds.min_decision_samples}"
        )
    reasons.extend(_breach_reasons(metrics, thresholds))
    return GateVerdict(not reasons, reasons, metrics.to_dict())


def _breach_reasons(metrics: Metrics, thresholds: Thresholds) -> list[str]:
    """只对已可测量的指标判越界；无缺陷/无良品不是越界，而是无法评估。"""

    reasons: list[str] = []
    if metrics.recall is not None and metrics.recall < thresholds.min_recall:
        reasons.append(
            f"缺陷召回 {metrics.recall:.4f} 低于门槛 {thresholds.min_recall:.4f}"
        )
    if (
        metrics.false_reject_rate is not None
        and metrics.false_reject_rate > thresholds.max_false_reject_rate
    ):
        reasons.append(
            f"误剔除率 {metrics.false_reject_rate:.4f} 高于门槛 "
            f"{thresholds.max_false_reject_rate:.4f}"
        )
    if (
        metrics.latency_p95_ms is not None
        and metrics.latency_p95_ms > thresholds.max_latency_ms
    ):
        reasons.append(
            f"p95 时延 {metrics.latency_p95_ms:.1f}ms 高于门槛 "
            f"{thresholds.max_latency_ms:.1f}ms"
        )
    return reasons


def safety_breaches(samples: list[Sample], thresholds: Thresholds) -> list[str]:
    """流式安全监控：样本一到即可发现越界，不要求凑满判定样本量。"""

    return _breach_reasons(evaluate(samples), thresholds)


# --- 影子比对 ------------------------------------------------------------


@dataclass(frozen=True)
class ShadowComparison:
    pairs: int
    disagreements: int

    @property
    def divergence_rate(self) -> float | None:
        return self.disagreements / self.pairs if self.pairs else None


def compare_shadow(pairs: list[tuple[bool, bool]]) -> ShadowComparison:
    """pairs 为 (在役模型判废, 候选模型判废)。"""

    disagreements = sum(1 for in_prod, candidate in pairs if in_prod != candidate)
    return ShadowComparison(len(pairs), disagreements)


# --- 推理回执 ------------------------------------------------------------


@dataclass(frozen=True)
class Receipt:
    receipt_id: str
    station_id: str
    bundle_id: str
    occurred_at: datetime
    received_at: datetime
    samples: list[SampleInput]
    batch_id: str | None = None
    key_id: str | None = None
    signature: bytes | None = None

    def signing_message(self) -> bytes:
        return canonical_json(
            [
                "receipt@v1",
                self.receipt_id,
                self.station_id,
                self.bundle_id,
                self.batch_id,
                fmt_ts(self.occurred_at),
                [
                    [s.sample_id, s.is_defect, s.model_reject, s.latency_ms]
                    for s in self.samples
                ],
            ]
        )


def validate_receipt(receipt: Receipt) -> None:
    if not receipt.receipt_id.strip():
        raise DomainError("receipt_id 为空")
    if not receipt.station_id.strip():
        raise DomainError("station_id 为空")
    if not receipt.bundle_id.strip():
        raise DomainError("bundle_id 为空")
    if receipt.received_at < receipt.occurred_at:
        raise DomainError("回执 received_at 早于 occurred_at")
    if not receipt.samples:
        raise DomainError("回执没有任何推理样本")
    ids = [s.sample_id for s in receipt.samples]
    if len(ids) != len(set(ids)):
        raise DomainError("回执内 sample_id 重复")
    for sample in receipt.samples:
        if sample.latency_ms < 0:
            raise DomainError("推理时延不能为负")
    if (receipt.signature is None) != (receipt.key_id is None):
        raise DomainError("回执签名与 key_id 必须同时出现或同时省略")


# --- 发布波次与工位状态 ---------------------------------------------------


@dataclass(frozen=True)
class Release:
    release_id: str
    bundle_id: str
    stations: tuple[str, ...]
    created_by: str
    approved_by: str | None
    approved_at: datetime | None
    frozen: bool
    freeze_reason: str | None
    created_at: datetime


@dataclass(frozen=True)
class StationState:
    station_id: str
    release_id: str
    bundle_id: str
    stage: Stage
    confirmed: bool
    since: datetime

    def assert_can_advance(self, target: Stage) -> None:
        current_idx = STAGE_ORDER.index(self.stage)
        target_idx = STAGE_ORDER.index(target)
        if target_idx <= current_idx:
            raise DomainError(
                f"工位 {self.station_id} 已处于 {self.stage.value}，"
                f"不能进入 {target.value}"
            )
        if target_idx != current_idx + 1:
            raise DomainError("每次只能推进一个发布阶段")


@dataclass(frozen=True)
class StageInterval:
    """工位在某一时间段内实际生效的组合（据 occurred_at 重建）。"""

    station_id: str
    bundle_id: str | None
    stage: Stage
    started_at: datetime
    ended_at: datetime | None
    confirmed: bool


def merge_intervals(intervals: list[StageInterval]) -> list[StageInterval]:
    """检查同一工位区间不得重叠，并按开始时间排序。"""

    result = sorted(intervals, key=lambda item: (item.station_id, item.started_at))
    by_station: dict[str, list[StageInterval]] = {}
    for interval in result:
        by_station.setdefault(interval.station_id, []).append(interval)
    for rows in by_station.values():
        for earlier, later in zip(rows, rows[1:]):
            if earlier.ended_at is None or earlier.ended_at > later.started_at:
                raise DomainError(
                    f"工位 {earlier.station_id} 在 {fmt_ts(later.started_at)} "
                    "同时属于两个发布阶段"
                )
    return result


# --- 生产批次封存 --------------------------------------------------------


@dataclass(frozen=True)
class BatchSeal:
    batch_id: str
    sealed_at: datetime
    stats: dict[str, object]
    receipt_ids: tuple[str, ...]


@dataclass(frozen=True)
class SealedSupplement:
    """封存后才到齐的回执：只做可审计补充，绝不改写封存统计。"""

    batch_id: str
    receipt_id: str
    station_id: str
    bundle_id: str
    sample_count: int
    occurred_at: datetime
    received_at: datetime


# --- 规范化 JSON（签名与指纹用） -----------------------------------------


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data, validate=True)
