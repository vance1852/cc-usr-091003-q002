"""把工厂既有事件流（EventEnvelope）幂等投影到放行平台。

事件按 occurred_at 全序处理；已处理事件记入投影水位，整个重放可
反复执行而不产生重复副作用（重启安全）。处理失败的事件被隔离到
dead_letter 表并中止，等待人工核对，绝不静默跳过。
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from .contracts import EventEnvelope
from .domain import (
    DomainError,
    Receipt,
    SampleInput,
    b64d,
    parse_ts,
)
from .service import DuplicateReceipt, ReleasePlatform


@dataclass(frozen=True)
class ProjectionStats:
    applied: int
    skipped: int
    dead_lettered: int
    outcomes: dict[str, Any]


class EventProjector:
    def __init__(self, platform: ReleasePlatform) -> None:
        self.platform = platform
        self.platform.store._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS projection_cursor (
                event_id TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL,
                outcome_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS projection_dead_letter (
                event_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                error TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );
            """
        )

    def _is_applied(self, event_id: str) -> bool:
        row = self.platform.store.query_one(
            "SELECT 1 FROM projection_cursor WHERE event_id=?", (event_id,)
        )
        return row is not None

    def _mark(self, event_id: str, outcome: dict[str, Any], now: str) -> None:
        self.platform.store.execute(
            "INSERT INTO projection_cursor(event_id, applied_at, outcome_json) VALUES (?,?,?)",
            (event_id, now, json.dumps(outcome, ensure_ascii=False, sort_keys=True)),
        )

    def replay(self, events: list[EventEnvelope]) -> ProjectionStats:
        # 按平台实际观测顺序（received_at）处理：断网迟到回执因此排在
        # 换线/封存等事件之后，真实复现"补数晚到"的现场。
        ordered = sorted(events, key=lambda e: (parse_ts(e.received_at), e.event_id))
        applied = skipped = dead = 0
        outcomes: dict[str, Any] = {"events": []}
        for event in ordered:
            if self._is_applied(event.event_id):
                skipped += 1
                continue
            # 平台时钟由事件接收时间显式驱动，协议解析不读系统时间。
            self.platform.clock = lambda ev=event: parse_ts(ev.received_at)
            try:
                with self.platform.store.transaction():
                    outcome = self.apply(event)
                    self._mark(
                        event.event_id, outcome,
                        event.received_at,  # 不读系统时钟
                    )
                applied += 1
                outcomes["events"].append(
                    {"event_id": event.event_id, "kind": event.kind, "outcome": outcome}
                )
            except (DomainError, sqlite3.Error) as exc:
                self._dead_letter(event, exc)
                dead += 1
                outcomes["events"].append(
                    {"event_id": event.event_id, "kind": event.kind,
                     "error": str(exc)}
                )
                continue
        return ProjectionStats(applied, skipped, dead, outcomes)

    def _dead_letter(self, event: EventEnvelope, exc: Exception) -> None:
        with self.platform.store.transaction():
            self.platform.store.execute(
                """INSERT OR REPLACE INTO projection_dead_letter
                   (event_id, kind, occurred_at, error, raw_json)
                   VALUES (?,?,?,?,?)""",
                (event.event_id, event.kind, event.occurred_at, str(exc),
                 json.dumps(event.attributes, ensure_ascii=False, sort_keys=True)),
            )

    # --- 事件分发 --------------------------------------------------------

    def apply(self, event: EventEnvelope) -> dict[str, Any]:
        handler = getattr(self, f"_on_{event.kind}", None)
        if handler is None:
            raise DomainError(f"未知事件类型：{event.kind}")
        return handler(event)

    def _attrs(self, event: EventEnvelope, *names: str) -> tuple[Any, ...]:
        missing = [name for name in names if name not in event.attributes]
        if missing:
            raise DomainError(
                f"事件 {event.event_id} 缺少字段：{'、'.join(missing)}"
            )
        return tuple(event.attributes[name] for name in names)

    def _on_signing_key_registered(self, event: EventEnvelope) -> dict[str, Any]:
        from .crypto import RsaPublicKey

        key_id, jwk = self._attrs(event, "key_id", "jwk")
        self.platform.register_key(key_id, RsaPublicKey.from_jwk(jwk))
        return {"key_id": key_id}

    def _on_model_registered(self, event: EventEnvelope) -> dict[str, Any]:
        model_id, digest, signature_b64, key_id, created_by = self._attrs(
            event, "model_id", "digest", "signature", "key_id", "created_by"
        )
        self.platform.register_model(
            model_id, digest, b64d(signature_b64), key_id, created_by=created_by
        )
        return {"model_id": model_id}

    def _on_calibration_registered(self, event: EventEnvelope) -> dict[str, Any]:
        calib_id, station_id, digest, created_by = self._attrs(
            event, "calib_id", "station_id", "digest", "created_by"
        )
        sig_b64 = event.attributes.get("signature")
        key_id = event.attributes.get("key_id")
        self.platform.register_calibration(
            calib_id, station_id, digest, created_by=created_by,
            signature=b64d(sig_b64) if sig_b64 else None,
            key_id=key_id,
        )
        return {"calib_id": calib_id, "station_id": station_id}

    def _on_recipe_registered(self, event: EventEnvelope) -> dict[str, Any]:
        from .domain import Thresholds

        (recipe_id, created_by, t) = self._attrs(
            event, "recipe_id", "created_by", "thresholds"
        )
        thresholds = Thresholds(
            recipe_id=recipe_id,
            min_recall=float(t["min_recall"]),
            max_false_reject_rate=float(t["max_false_reject_rate"]),
            max_latency_ms=float(t["max_latency_ms"]),
            min_decision_samples=int(t["min_decision_samples"]),
            canary_cap=int(t["canary_cap"]),
        )
        self.platform.register_recipe(recipe_id, thresholds, created_by=created_by)
        return {"recipe_id": recipe_id}

    def _on_bundle_registered(self, event: EventEnvelope) -> dict[str, Any]:
        bundle_id, model_id, recipe_id, calibs, created_by = self._attrs(
            event, "bundle_id", "model_id", "recipe_id", "calibs", "created_by"
        )
        self.platform.create_bundle(
            bundle_id, model_id, recipe_id, dict(calibs), created_by=created_by
        )
        return {"bundle_id": bundle_id}

    def _on_stable_provisioned(self, event: EventEnvelope) -> dict[str, Any]:
        station_id, bundle_id, actor = self._attrs(
            event, "station_id", "bundle_id", "actor"
        )
        self.platform.provision_stable(station_id, bundle_id, actor=actor)
        return {"station_id": station_id, "bundle_id": bundle_id}

    def _on_release_created(self, event: EventEnvelope) -> dict[str, Any]:
        release_id, bundle_id, stations, created_by = self._attrs(
            event, "release_id", "bundle_id", "stations", "created_by"
        )
        self.platform.create_release(
            release_id, bundle_id, list(stations), created_by=created_by
        )
        return {"release_id": release_id}

    def _on_release_approved(self, event: EventEnvelope) -> dict[str, Any]:
        release_id, approver = self._attrs(event, "release_id", "approver")
        self.platform.approve_release(release_id, approver=approver)
        return {"release_id": release_id}

    def _on_shadow_started(self, event: EventEnvelope) -> dict[str, Any]:
        release_id, station_id, actor = self._attrs(
            event, "release_id", "station_id", "actor"
        )
        self.platform.start_shadow(release_id, station_id, actor=actor)
        return {"release_id": release_id, "station_id": station_id}

    def _on_shadow_observed(self, event: EventEnvelope) -> dict[str, Any]:
        (release_id, station_id, sample_id, is_defect,
         incumbent_reject, candidate_reject, latency_ms) = self._attrs(
            event, "release_id", "station_id", "sample_id", "is_defect",
            "incumbent_reject", "candidate_reject", "latency_ms"
        )
        self.platform.record_shadow(
            release_id, station_id, sample_id,
            is_defect=bool(is_defect), incumbent_reject=bool(incumbent_reject),
            candidate_reject=bool(candidate_reject), latency_ms=float(latency_ms),
        )
        return {"sample_id": sample_id}

    def _on_canary_started(self, event: EventEnvelope) -> dict[str, Any]:
        release_id, station_id, operator = self._attrs(
            event, "release_id", "station_id", "operator"
        )
        self.platform.start_canary(release_id, station_id, operator=operator)
        return {"release_id": release_id, "station_id": station_id}

    def _on_station_acknowledged(self, event: EventEnvelope) -> dict[str, Any]:
        release_id, station_id, operator = self._attrs(
            event, "release_id", "station_id", "operator"
        )
        self.platform.confirm_station(release_id, station_id, operator=operator)
        return {"release_id": release_id, "station_id": station_id}

    def _on_restored_confirmed(self, event: EventEnvelope) -> dict[str, Any]:
        station_id, operator = self._attrs(event, "station_id", "operator")
        self.platform.confirm_restored(station_id, operator=operator)
        return {"station_id": station_id}

    def _on_inference_reported(self, event: EventEnvelope) -> dict[str, Any]:
        (receipt_id, station_id, bundle_id, occurred_at, received_at,
         samples) = self._attrs(
            event, "receipt_id", "station_id", "bundle_id",
            "occurred_at", "received_at", "samples"
        )
        key_id = event.attributes.get("key_id")
        signature_b64 = event.attributes.get("signature")
        receipt = Receipt(
            receipt_id=receipt_id,
            station_id=station_id,
            bundle_id=bundle_id,
            occurred_at=parse_ts(occurred_at),
            received_at=parse_ts(received_at),
            samples=[
                SampleInput(
                    sample_id=s["sample_id"],
                    is_defect=bool(s["is_defect"]),
                    model_reject=bool(s["model_reject"]),
                    latency_ms=float(s["latency_ms"]),
                )
                for s in samples
            ],
            batch_id=event.attributes.get("batch_id"),
            key_id=key_id,
            signature=b64d(signature_b64) if signature_b64 else None,
        )
        try:
            result = self.platform.ingest_receipt(receipt)
        except DuplicateReceipt:
            return {"receipt_id": receipt_id, "status": "duplicate"}
        return {
            "receipt_id": receipt_id,
            "status": result.status,
            "stage": result.stage,
            "frozen": result.frozen,
            "rolled_back": list(result.rolled_back_stations),
        }

    def _on_batch_sealed(self, event: EventEnvelope) -> dict[str, Any]:
        batch_id, actor = self._attrs(event, "batch_id", "actor")
        result = self.platform.seal_batch(batch_id, actor=actor)
        return {"batch_id": batch_id, "already_sealed": result["already_sealed"]}
