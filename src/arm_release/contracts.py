"""现场事件信封与样例加载规则。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


class ContractError(ValueError):
    """表示输入不符合现场交换契约。"""


def _timestamp(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ContractError(f"{field} 必须是字符串")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError(f"{field} 不是有效时间") from exc
    if parsed.tzinfo is None:
        raise ContractError(f"{field} 必须包含时区")
    return value


@dataclass(frozen=True)
class EventEnvelope:
    """保存不可变事件信封，未知属性继续随事件传递。"""

    event_id: str
    kind: str
    occurred_at: str
    received_at: str
    attributes: dict[str, Any]

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "EventEnvelope":
        required = ("event_id", "kind", "occurred_at", "received_at", "attributes")
        missing = [field for field in required if field not in raw]
        if missing:
            raise ContractError("缺少字段：" + "、".join(missing))
        if not isinstance(raw["event_id"], str) or not raw["event_id"].strip():
            raise ContractError("event_id 不能为空")
        if not isinstance(raw["kind"], str) or not raw["kind"].strip():
            raise ContractError("kind 不能为空")
        if not isinstance(raw["attributes"], dict):
            raise ContractError("attributes 必须是对象")
        return cls(
            event_id=raw["event_id"],
            kind=raw["kind"],
            occurred_at=_timestamp(raw["occurred_at"], "occurred_at"),
            received_at=_timestamp(raw["received_at"], "received_at"),
            attributes=dict(raw["attributes"]),
        )


def load_events(path: str | Path) -> tuple[str, list[EventEnvelope]]:
    """读取一个场景文件并拒绝重复的事件标识。"""

    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("scenario"), str):
        raise ContractError("场景文件缺少 scenario")
    if not isinstance(raw.get("events"), list):
        raise ContractError("场景文件缺少 events 数组")
    events = [EventEnvelope.from_dict(item) for item in raw["events"]]
    identifiers = [event.event_id for event in events]
    if len(identifiers) != len(set(identifiers)):
        raise ContractError("场景内 event_id 重复")
    return raw["scenario"], events