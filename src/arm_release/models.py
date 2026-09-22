"""放行平台的领域类型：产品配方门槛、发布组合、回执与标定快照。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from .contracts import ContractError


class PlatformError(ContractError):
    """领域规则被违反（非法状态迁移、证据不足等）。"""


class Stage(str, Enum):
    """一座工位对一个候选组合可能经历的发布阶段。"""

    SHADOW = "shadow"        # 影子比对：候选只记录、不驱动机械臂
    CANARY = "canary"        # 限量试运行
    ROLLOUT = "rollout"      # 扩围中
    ACTIVE = "active"        # 全量生效，成为新的稳定组合


# 阶段必须按序推进
STAGE_ORDER = [Stage.SHADOW, Stage.CANARY, Stage.ROLLOUT, Stage.ACTIVE]


def parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise PlatformError("时间戳必须包含时区：" + value)
    return dt


def require_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PlatformError(f"{field_name} 不能为空")
    return value


@dataclass(frozen=True)
class Thresholds:
    """产品配方的安全门槛：缺陷召回下限、误剔除率上限、P95 推理时延上限。"""

    min_defect_recall: float
    max_false_reject_rate: float
    max_latency_p95_ms: float

    def __post_init__(self) -> None:
        for name in ("min_defect_recall", "max_false_reject_rate"):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise PlatformError(f"{name} 必须落在 [0, 1]")
        if self.max_latency_p95_ms <= 0:
            raise PlatformError("max_latency_p95_ms 必须为正数")

    def to_dict(self) -> dict[str, Any]:
        return {
            "min_defect_recall": self.min_defect_recall,
            "max_false_reject_rate": self.max_false_reject_rate,
            "max_latency_p95_ms": self.max_latency_p95_ms,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Thresholds":
        try:
            return cls(
                min_defect_recall=float(raw["min_defect_recall"]),
                max_false_reject_rate=float(raw["max_false_reject_rate"]),
                max_latency_p95_ms=float(raw["max_latency_p95_ms"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PlatformError("配方门槛字段缺失或非法") from exc


@dataclass(frozen=True)
class ModelArtifact:
    """工厂模型清单中的视觉模型条目（已签名）。"""

    model_id: str
    version: str
    digest: str
    kid: str
    signature: str
    payload: dict[str, Any]

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ModelArtifact":
        model_id = require_str(raw.get("model_id"), "model_id")
        version = require_str(raw.get("version"), "version")
        digest = require_str(raw.get("digest"), "digest")
        kid = require_str(raw.get("kid"), "kid")
        signature = require_str(raw.get("signature"), "signature")
        payload = raw.get("payload")
        if not isinstance(payload, dict):
            raise PlatformError("模型缺少签名载荷 payload")
        return cls(model_id, version, digest, kid, signature, payload)


@dataclass(frozen=True)
class CalibrationSnapshot:
    """相机标定快照：自身带摘要，随组合不可替换。"""

    snapshot_id: str
    camera_id: str
    digest: str
    taken_at: str
    intrinsics: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CalibrationSnapshot":
        snapshot_id = require_str(raw.get("snapshot_id"), "snapshot_id")
        camera_id = require_str(raw.get("camera_id"), "camera_id")
        digest = require_str(raw.get("digest"), "digest")
        taken_at = require_str(raw.get("taken_at"), "taken_at")
        parse_ts(taken_at)
        intrinsics = raw.get("intrinsics", {})
        if not isinstance(intrinsics, dict):
            raise PlatformError("标定内参必须是对象")
        return cls(snapshot_id, camera_id, digest, taken_at, dict(intrinsics))


@dataclass(frozen=True)
class Recipe:
    """产品配方：门槛与当前生效版本。"""

    recipe: str
    version: str
    thresholds: Thresholds


@dataclass(frozen=True)
class Bundle:
    """不可拆开的发布组合：模型 + 相机标定 + 产品配方。"""

    bundle_id: str
    recipe: str
    recipe_version: str
    model: ModelArtifact
    calibration: CalibrationSnapshot

    def manifest(self) -> dict[str, Any]:
        """被签名与审批绑定的组合清单，三者缺一不可。"""

        return {
            "bundle_id": self.bundle_id,
            "recipe": self.recipe,
            "recipe_version": self.recipe_version,
            "model": {
                "model_id": self.model.model_id,
                "version": self.model.version,
                "digest": self.model.digest,
            },
            "calibration": {
                "snapshot_id": self.calibration.snapshot_id,
                "camera_id": self.calibration.camera_id,
                "digest": self.calibration.digest,
            },
        }
