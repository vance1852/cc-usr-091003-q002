"""模型放行平台核心服务。

所有写操作都在单条 SQLite 事务内完成；时间通过可注入时钟获取，
协议解析与统计不隐式读取系统时间。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from .crypto import (
    PublicKey,
    SignatureError,
    b64decode,
    verify_payload,
)
from .models import (
    Bundle,
    CalibrationSnapshot,
    ModelArtifact,
    PlatformError,
    Stage,
    Thresholds,
    parse_ts,
    require_str,
)
from .stats import GateRequirement, Metrics
from .store import Store

# 终止一座工位候选流水线的事件
TERMINAL_ACTIONS = {"station_active", "rolled_back"}
# 候选真正驱动机械臂的阶段（影子只记录不驱动）
SERVING_PHASES = {Stage.CANARY.value, Stage.ROLLOUT.value}


@dataclass(frozen=True)
class GateConfig:
    """各阶段放行所需样本量。"""

    shadow: GateRequirement = field(default_factory=lambda: GateRequirement(30, 30))
    canary: GateRequirement = field(default_factory=lambda: GateRequirement(50))
    rollout: GateRequirement = field(default_factory=lambda: GateRequirement(100))

    def for_phase(self, phase: str) -> GateRequirement:
        return {
            Stage.SHADOW.value: self.shadow,
            Stage.CANARY.value: self.canary,
            Stage.ROLLOUT.value: self.rollout,
        }[phase]


@dataclass(frozen=True)
class ReceiptResult:
    outcome: str                       # counted | duplicate | quarantined
    receipt_id: str
    bundle_id: str
    counted_phase: str | None = None
    quarantine_reason: str | None = None
    triggered_freeze: bool = False


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Platform:
    def __init__(
        self,
        store: Store,
        gates: GateConfig | None = None,
        clock: Callable[[], datetime] = _utcnow,
    ):
        self.store = store
        self.gates = gates or GateConfig()
        self.clock = clock

    def _now(self) -> str:
        now = self.clock()
        if now.tzinfo is None:
            raise PlatformError("时钟必须返回带时区的时间")
        return now.isoformat()

    # ------------------------------------------------------------------
    # 信任清单：公钥 / 模型 / 标定 / 配方
    # ------------------------------------------------------------------

    def add_trusted_key(self, public_key: PublicKey, role: str) -> None:
        if role not in ("model", "release"):
            raise PlatformError("公钥角色必须是 model 或 release")
        with self.store.transaction() as tx:
            if tx.get_key(public_key.kid):
                raise PlatformError(f"公钥已存在：{public_key.kid}")
            tx.add_key(public_key.kid, role, public_key.to_dict()["x"], self._now())

    def _load_key(self, tx: Store, kid: str, role: str) -> PublicKey:
        row = tx.get_key(kid)
        if row is None:
            raise PlatformError(f"不受信任的签名密钥：{kid}")
        if row["role"] != role:
            raise PlatformError(f"密钥 {kid} 角色不匹配（需要 {role}）")
        return PublicKey(kid=kid, raw=b64decode(row["x"]))

    def register_model(self, envelope: dict[str, Any]) -> str:
        """验签并登记一份模型清单条目，返回 (model_id, version)。"""

        artifact = ModelArtifact.from_dict(envelope)
        with self.store.transaction() as tx:
            if tx.get_model(artifact.model_id, artifact.version):
                raise PlatformError("模型版本已登记")
            key = self._load_key(tx, artifact.kid, "model")
            try:
                verify_payload(key, artifact.payload, artifact.signature)
            except SignatureError as exc:
                raise PlatformError("模型签名无效") from exc
            signed_digest = artifact.payload.get("digest")
            if signed_digest != artifact.digest:
                raise PlatformError("模型摘要与签名载荷不一致")
            tx.add_model(artifact, self._now())
        return f"{artifact.model_id}@{artifact.version}"

    def register_calibration(self, envelope: dict[str, Any]) -> str:
        snap = CalibrationSnapshot.from_dict(envelope)
        with self.store.transaction() as tx:
            if tx.get_calibration(snap.snapshot_id):
                raise PlatformError("标定快照已登记")
            tx.add_calibration(snap, self._now())
        return snap.snapshot_id

    def register_recipe(
        self, recipe: str, version: str, thresholds: Thresholds
    ) -> None:
        with self.store.transaction() as tx:
            if tx.get_recipe(recipe, version):
                raise PlatformError("配方版本已登记")
            tx.add_recipe(
                recipe, version, json.dumps(thresholds.to_dict()), self._now()
            )

    def _thresholds(self, tx: Store, recipe: str, version: str) -> Thresholds:
        row = tx.get_recipe(recipe, version)
        if row is None:
            raise PlatformError(f"配方未登记：{recipe}@{version}")
        return Thresholds.from_dict(json.loads(row["thresholds_json"]))

    # ------------------------------------------------------------------
    # 发布组合：模型 + 标定 + 配方，整体签名、整体审批
    # ------------------------------------------------------------------

    def register_bundle(self, envelope: dict[str, Any]) -> str:
        for name in ("bundle_id", "kid", "signature"):
            require_str(envelope.get(name), name)
        parts = envelope.get("parts")
        if not isinstance(parts, dict):
            raise PlatformError("组合缺少 parts")
        try:
            model_ref = (
                require_str(parts["model"].get("model_id"), "model_id"),
                require_str(parts["model"].get("version"), "version"),
            )
            calibration_id = require_str(
                parts["calibration"].get("snapshot_id"), "snapshot_id"
            )
            recipe = require_str(parts.get("recipe"), "recipe")
            recipe_version = require_str(parts.get("recipe_version"), "recipe_version")
        except (KeyError, AttributeError) as exc:
            raise PlatformError("组合 parts 结构不完整") from exc

        with self.store.transaction() as tx:
            if tx.get_bundle(envelope["bundle_id"]):
                raise PlatformError("发布组合已登记")
            m_row = tx.get_model(*model_ref)
            if m_row is None:
                raise PlatformError("组合引用了未登记的模型")
            c_row = tx.get_calibration(calibration_id)
            if c_row is None:
                raise PlatformError("组合引用了未登记的标定快照")
            if tx.get_recipe(recipe, recipe_version) is None:
                raise PlatformError("组合引用了未登记的配方版本")

            model = ModelArtifact(
                m_row["model_id"],
                m_row["version"],
                m_row["digest"],
                m_row["kid"],
                m_row["signature"],
                json.loads(m_row["payload_json"]),
            )
            cal = CalibrationSnapshot(
                c_row["snapshot_id"],
                c_row["camera_id"],
                c_row["digest"],
                c_row["taken_at"],
                json.loads(c_row["payload_json"]).get("intrinsics", {}),
            )
            bundle = Bundle(
                envelope["bundle_id"], recipe, recipe_version, model, cal
            )
            manifest = bundle.manifest()
            if parts.get("manifest") is not None and parts["manifest"] != manifest:
                raise PlatformError("组合清单与引用部件不一致")
            key = self._load_key(tx, envelope["kid"], "release")
            try:
                verify_payload(key, manifest, envelope["signature"])
            except SignatureError as exc:
                raise PlatformError("发布组合签名无效") from exc
            tx.add_bundle(bundle, envelope["signature"], envelope["kid"], self._now())
            tx.init_rollout(bundle.bundle_id)
        return envelope["bundle_id"]

    def approve_bundle(self, bundle_id: str, approver: str) -> None:
        require_str(approver, "approver")
        with self.store.transaction() as tx:
            row = tx.get_bundle(bundle_id)
            if row is None:
                raise PlatformError("发布组合不存在")
            if row["approved_by"]:
                raise PlatformError("组合已审批，审批不可改写")
            tx.approve_bundle(bundle_id, approver, self._now())
            tx.add_stage_event(
                "-", bundle_id, "bundle_approved", self._now(), actor=approver
            )

    def _require_approved(self, tx: Store, bundle_id: str):
        row = tx.get_bundle(bundle_id)
        if row is None:
            raise PlatformError("发布组合不存在")
        if not row["approved_by"]:
            raise PlatformError("组合尚未经质量审批")
        return row

    def establish_stable(
        self, station_id: str, bundle_id: str, at: str | None = None
    ) -> None:
        """登记/初始化工位的在役稳定组合（也用于事故时间线重建）。"""

        at = at or self._now()
        parse_ts(at)
        with self.store.transaction() as tx:
            self._require_approved(tx, bundle_id)
            if tx.get_pipeline(station_id) is not None:
                raise PlatformError("工位存在未终结的候选流水线")
            tx.upsert_stable(station_id, bundle_id, at)
            tx.add_stage_event(
                station_id, bundle_id, "stable_established", at, phase="stable"
            )

    # ------------------------------------------------------------------
    # 阶段推进（执行人与审批人不得为同一人）
    # ------------------------------------------------------------------

    def _check_executor(self, bundle_row, executor: str) -> None:
        if not executor or not executor.strip():
            raise PlatformError("缺少执行人")
        if executor == bundle_row["approved_by"]:
            raise PlatformError("发布审批人与执行人为同一人，职责分离被拒绝")

    def start_shadow(self, station_id: str, bundle_id: str, executor: str) -> None:
        with self.store.transaction() as tx:
            bundle_row = self._require_approved(tx, bundle_id)
            self._check_executor(bundle_row, executor)
            rollout = tx.get_rollout(bundle_id)
            if rollout and rollout["frozen"]:
                raise PlatformError("组合已冻结，禁止启动新的放行流程")
            if tx.get_pipeline(station_id) is not None:
                raise PlatformError("工位已有进行中的候选流水线")
            stable = tx.get_stable(station_id)
            prev = stable["bundle_id"] if stable else None
            at = self._now()
            tx.upsert_pipeline(station_id, bundle_id, Stage.SHADOW.value, at, prev, executor)
            tx.add_stage_event(
                station_id, bundle_id, "shadow_started", at,
                phase=Stage.SHADOW.value, actor=executor,
            )

    def _gate_blockers(
        self, tx: Store, station_id: str, bundle_id: str, phase: str
    ) -> tuple[list[str], Metrics, Thresholds]:
        bundle_row = tx.get_bundle(bundle_id)
        thresholds = self._thresholds(
            tx, bundle_row["recipe"], bundle_row["recipe_version"]
        )
        metrics = self._window_metrics(tx, station_id, bundle_id, phase)
        blockers = self.gates.for_phase(phase).evaluate(metrics, thresholds)
        return blockers, metrics, thresholds

    def promote(
        self, station_id: str, bundle_id: str, executor: str
    ) -> str:
        """按序推进 shadow→canary→rollout→active。"""

        with self.store.transaction() as tx:
            bundle_row = self._require_approved(tx, bundle_id)
            self._check_executor(bundle_row, executor)
            pipeline = tx.get_pipeline(station_id)
            if pipeline is None or pipeline["bundle_id"] != bundle_id:
                raise PlatformError("工位不在该组合的候选流水线中")
            rollout = tx.get_rollout(bundle_id)
            if rollout and rollout["frozen"]:
                raise PlatformError("扩围已冻结，禁止继续推进")
            current = pipeline["phase"]
            idx = [s.value for s in Stage].index(current)
            if idx >= len(Stage) - 1:
                raise PlatformError("工位已在最终阶段")
            blockers, metrics, _ = self._gate_blockers(
                tx, station_id, bundle_id, current
            )
            if blockers:
                raise PlatformError(
                    f"门槛未通过（{current}）：" + "；".join(blockers)
                )
            next_phase = [s.value for s in Stage][idx + 1]
            at = self._now()
            action = {
                Stage.CANARY.value: "canary_started",
                Stage.ROLLOUT.value: "rollout_started",
                Stage.ACTIVE.value: "station_active",
            }[next_phase]
            tx.add_stage_event(
                station_id, bundle_id, action, at, phase=next_phase, actor=executor,
                detail={"gate_metrics": metrics.snapshot()},
            )
            if next_phase == Stage.ACTIVE.value:
                # 确认：候选成为新的稳定组合，流水线终结
                tx.upsert_stable(station_id, bundle_id, at)
                tx.delete_pipeline(station_id)
            else:
                tx.upsert_pipeline(
                    station_id,
                    bundle_id,
                    next_phase,
                    at,
                    pipeline["prev_bundle_id"],
                    pipeline["executor"],
                )
            return next_phase

    # ------------------------------------------------------------------
    # 回执接入：迟到归属、去重、越界冻结
    # ------------------------------------------------------------------

    def report_receipt(self, raw_receipt: dict[str, Any]) -> ReceiptResult:
        rid = require_str(raw_receipt.get("receipt_id"), "receipt_id")
        station_id = require_str(raw_receipt.get("station_id"), "station_id")
        bundle_id = require_str(raw_receipt.get("bundle_id"), "bundle_id")
        occurred_at = require_str(raw_receipt.get("occurred_at"), "occurred_at")
        received_at = require_str(raw_receipt.get("received_at"), "received_at")
        parse_ts(occurred_at)
        parse_ts(received_at)
        if parse_ts(received_at) < parse_ts(occurred_at):
            raise PlatformError("received_at 不能早于 occurred_at")
        truth = require_str(raw_receipt.get("truth"), "truth")
        decision = require_str(raw_receipt.get("decision"), "decision")
        if truth not in ("good", "defect") or decision not in ("accept", "reject"):
            raise PlatformError("truth/decision 取值非法")
        try:
            latency_ms = float(raw_receipt["latency_ms"])
        except (KeyError, TypeError, ValueError) as exc:
            raise PlatformError("latency_ms 缺失或非法") from exc
        if latency_ms < 0:
            raise PlatformError("latency_ms 不能为负")
        champion = raw_receipt.get("champion_decision")
        if champion is not None and champion not in ("accept", "reject"):
            raise PlatformError("champion_decision 取值非法")
        batch_id = raw_receipt.get("batch_id")

        with self.store.transaction() as tx:
            if tx.get_bundle(bundle_id) is None:
                raise PlatformError("回执引用了未知发布组合")
            # 重复回执只计一次（幂等）
            if tx.get_receipt(rid) is not None:
                return ReceiptResult("duplicate", rid, bundle_id)

            # 已封存批次：补数只隔离留证，绝不可改写封存统计
            if batch_id and tx.get_sealed_batch(batch_id) is not None:
                record = {
                    "receipt_id": rid, "station_id": station_id, "bundle_id": bundle_id,
                    "batch_id": batch_id, "occurred_at": occurred_at,
                    "received_at": received_at, "truth": truth, "decision": decision,
                    "latency_ms": latency_ms, "champion_decision": champion,
                    "counted_phase": "quarantined", "quarantined": True,
                    "raw": dict(raw_receipt),
                }
                tx.insert_receipt(record)
                return ReceiptResult(
                    "quarantined", rid, bundle_id,
                    quarantine_reason="batch_sealed_late_backfill",
                )

            phase = self._phase_at(tx, station_id, bundle_id, occurred_at)
            if phase is None:
                record = {
                    "receipt_id": rid, "station_id": station_id, "bundle_id": bundle_id,
                    "batch_id": batch_id, "occurred_at": occurred_at,
                    "received_at": received_at, "truth": truth, "decision": decision,
                    "latency_ms": latency_ms, "champion_decision": champion,
                    "counted_phase": "quarantined", "quarantined": True,
                    "raw": dict(raw_receipt),
                }
                tx.insert_receipt(record)
                return ReceiptResult(
                    "quarantined", rid, bundle_id,
                    quarantine_reason="no_execution_interval_at_occurred_at",
                )

            record = {
                "receipt_id": rid, "station_id": station_id, "bundle_id": bundle_id,
                "batch_id": batch_id, "occurred_at": occurred_at,
                "received_at": received_at, "truth": truth, "decision": decision,
                "latency_ms": latency_ms, "champion_decision": champion,
                "counted_phase": phase, "quarantined": False,
                "raw": dict(raw_receipt),
            }
            tx.insert_receipt(record)

            # 限量试运行/扩围窗口内，样本量一够就检查安全指标，越界即冻结
            triggered = False
            if phase in SERVING_PHASES:
                rollout = tx.get_rollout(bundle_id)
                if rollout is not None and not rollout["frozen"]:
                    bundle_row = tx.get_bundle(bundle_id)
                    thresholds = self._thresholds(
                        tx, bundle_row["recipe"], bundle_row["recipe_version"]
                    )
                    metrics = self._window_metrics(tx, station_id, bundle_id, phase)
                    required = self.gates.for_phase(phase).min_samples
                    if metrics.samples >= required and metrics.breaches(
                        thresholds, required
                    ):
                        self._freeze_locked(
                            tx,
                            bundle_id,
                            {
                                "station_id": station_id,
                                "phase": phase,
                                "breached": metrics.breaches(thresholds, required),
                                "evidence_receipt_id": rid,
                                "metrics": metrics.snapshot(),
                                "thresholds": thresholds.to_dict(),
                                "detected_at": received_at,
                            },
                        )
                        triggered = True
            return ReceiptResult("counted", rid, bundle_id, phase, triggered_freeze=triggered)

    def _phase_at(
        self, tx: Store, station_id: str, bundle_id: str, at_iso: str
    ) -> str | None:
        """按发生时刻判定回执实际归属的阶段/组合（迟到回执也能归位）。

        候选区间（时间线上互不重叠）优先匹配；影子期旧组合仍在役计 stable；
        一旦候选进入 canary/rollout，同时刻旧组合回执一律隔离。
        """

        t = parse_ts(at_iso)
        intervals = self._intervals_locked(tx, station_id)
        for start, end, bid, phase in intervals:
            if bid == bundle_id and start <= t < end:
                return phase
        # 落在在役稳定组合服役区间（且没有其他组合在服役）
        stable_row = tx.get_stable(station_id)
        if stable_row and stable_row["bundle_id"] == bundle_id:
            for start, end, _bid, phase in intervals:
                if phase in SERVING_PHASES and start <= t < end:
                    return None
            if self._stable_since_locked(tx, station_id, at_iso) is not None:
                return "stable"
        return None

    def _intervals_locked(
        self, tx: Store, station_id: str
    ) -> list[tuple[datetime, datetime, str, str]]:
        """把阶段事件流还原成 [起, 止) 区间，同一时刻按事件 id 定序。"""

        events = [
            e
            for e in tx.list_stage_events(station_id)
            if e["action"] not in ("stable_established", "bundle_approved")
        ]
        ordered = sorted(events, key=lambda e: (parse_ts(e["at_time"]), e["id"]))
        far = datetime.max.replace(tzinfo=timezone.utc)
        intervals: list[tuple[datetime, datetime, str, str]] = []
        current: tuple[datetime, str, str] | None = None
        for e in ordered:
            t = parse_ts(e["at_time"])
            if e["action"] in TERMINAL_ACTIONS:
                if current is not None:
                    intervals.append((current[0], t, current[1], current[2]))
                    current = None
                continue
            if current is not None:
                intervals.append((current[0], t, current[1], current[2]))
            current = (t, e["bundle_id"], e["phase"])
        if current is not None:
            intervals.append((current[0], far, current[1], current[2]))
        return intervals

    def _stable_since_locked(
        self, tx: Store, station_id: str, at_iso: str
    ) -> datetime | None:
        events = tx.list_stage_events(station_id)
        # 最近一次 stable_established / station_active 且不晚于 at
        t = parse_ts(at_iso)
        latest: datetime | None = None
        for e in events:
            if e["action"] in ("stable_established", "station_active"):
                et = parse_ts(e["at_time"])
                if et <= t and (latest is None or et > latest):
                    latest = et
        return latest

    def _window_metrics(
        self, tx: Store, station_id: str, bundle_id: str, phase: str
    ) -> Metrics:
        rows = tx.count_receipts(station_id, bundle_id, phase)
        m = Metrics()
        for r in rows:
            m.add(
                truth=r["truth"],
                decision=r["decision"],
                latency_ms=r["latency_ms"],
                champion_decision=r["champion_decision"],
            )
        return m

    # ------------------------------------------------------------------
    # 冻结与回滚
    # ------------------------------------------------------------------

    def freeze(self, bundle_id: str, reason: dict[str, Any], actor: str) -> None:
        with self.store.transaction() as tx:
            if tx.get_bundle(bundle_id) is None:
                raise PlatformError("发布组合不存在")
            rollout = tx.get_rollout(bundle_id)
            if rollout and rollout["frozen"]:
                raise PlatformError("组合已处于冻结状态")
            payload = dict(reason)
            payload["actor"] = actor
            self._freeze_locked(tx, bundle_id, payload)

    def _freeze_locked(self, tx: Store, bundle_id: str, reason: dict[str, Any]) -> None:
        at = reason.get("detected_at") or self._now()
        tx.freeze_rollout(bundle_id, at, reason)
        tx.add_stage_event(
            "-", bundle_id, "rollout_frozen", at, actor=reason.get("actor"),
            detail=reason,
        )
        # 尚未确认（仍有候选流水线）的工位一律退回上一稳定组合
        for pipeline in tx.list_pipelines(bundle_id):
            station_id = pipeline["station_id"]
            prev = pipeline["prev_bundle_id"]
            stable = tx.get_stable(station_id)
            serving_before = pipeline["phase"] in SERVING_PHASES
            tx.add_stage_event(
                station_id, bundle_id, "rolled_back", at,
                phase=pipeline["phase"],
                detail={
                    "reverted_to": prev or (stable["bundle_id"] if stable else None),
                    "from_phase": pipeline["phase"],
                    "was_serving_candidate": serving_before,
                },
            )
            tx.delete_pipeline(station_id)

    # ------------------------------------------------------------------
    # 批次封存（统计快照不可变）
    # ------------------------------------------------------------------

    def seal_batch(self, batch_id: str) -> dict[str, Any]:
        with self.store.transaction() as tx:
            if tx.get_sealed_batch(batch_id) is not None:
                raise PlatformError("批次已封存")
            rows = tx.list_batch_receipts(batch_id)
            per_station: dict[tuple[str, str], Metrics] = {}
            for r in rows:
                key = (r["station_id"], r["bundle_id"])
                per_station.setdefault(key, Metrics()).add(
                    truth=r["truth"],
                    decision=r["decision"],
                    latency_ms=r["latency_ms"],
                    champion_decision=r["champion_decision"],
                )
            summary = {
                "batch_id": batch_id,
                "receipts": len(rows),
                "stations": [],
            }
            for (station_id, bundle_id), metrics in sorted(per_station.items()):
                snap = metrics.snapshot()
                tx.add_sealed_stat(batch_id, station_id, bundle_id, snap)
                summary["stations"].append(
                    {"station_id": station_id, "bundle_id": bundle_id, "metrics": snap}
                )
            at = self._now()
            tx.seal_batch(batch_id, at, summary)
        return summary

    def sealed_batch_summary(self, batch_id: str) -> dict[str, Any]:
        row = self.store.get_sealed_batch(batch_id)
        if row is None:
            raise PlatformError("批次未封存")
        return json.loads(row["summary_json"])

    # ------------------------------------------------------------------
    # 给机械臂的在役视图：下发前重新验签，绝不返回未签名组合
    # ------------------------------------------------------------------

    def _verified_serving(self, tx: Store, bundle_id: str, phase: str | None) -> dict[str, Any]:
        b = tx.get_bundle(bundle_id)
        if b is None:
            raise PlatformError("组合不存在，拒绝下发")
        if not b["approved_by"]:
            raise PlatformError("组合未经审批，拒绝下发")
        m = tx.get_model(b["model_id"], b["model_version"])
        c = tx.get_calibration(b["calibration_id"])
        if m is None or c is None:
            raise PlatformError("组合部件缺失，拒绝下发")
        # 下发路径上重新验签模型与组合清单
        model_key = self._load_key(tx, m["kid"], "model")
        model_payload = json.loads(m["payload_json"])
        try:
            verify_payload(model_key, model_payload, m["signature"])
        except SignatureError as exc:
            raise PlatformError("模型签名复核失败，拒绝下发") from exc
        release_key = self._load_key(tx, b["kid"], "release")
        manifest = json.loads(b["manifest_json"])
        try:
            verify_payload(release_key, manifest, b["signature"])
        except SignatureError as exc:
            raise PlatformError("组合签名复核失败，拒绝下发") from exc
        view = {
            "bundle_id": b["bundle_id"],
            "model_id": m["model_id"],
            "model_version": m["version"],
            "model_digest": m["digest"],
            "model_signature": m["signature"],
            "calibration_id": c["snapshot_id"],
            "calibration_digest": c["digest"],
            "recipe": b["recipe"],
            "recipe_version": b["recipe_version"],
        }
        if phase is not None:
            view["phase"] = phase
        return view

    def serving_view(self, station_id: str) -> dict[str, Any]:
        with self.store.transaction() as tx:
            pipeline = tx.get_pipeline(station_id)
            candidate = None
            if pipeline is not None:
                candidate = {
                    "bundle_id": pipeline["bundle_id"],
                    "phase": pipeline["phase"],
                    "drives_arm": pipeline["phase"] in SERVING_PHASES,
                }
            stable = tx.get_stable(station_id)
            stable_view = None
            if stable is not None:
                stable_view = self._verified_serving(tx, stable["bundle_id"], None)
            arm_serves = None
            if candidate and candidate["drives_arm"]:
                arm_serves = self._verified_serving(
                    tx, candidate["bundle_id"], candidate["phase"]
                )
            return {
                "station_id": station_id,
                "arm_serves": arm_serves or stable_view,
                "shadow_candidate": candidate if candidate and not candidate["drives_arm"] else None,
                "stable": stable_view,
            }

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------

    def station_status(self, station_id: str) -> dict[str, Any]:
        pipeline = self.store.get_pipeline(station_id)
        stable = self.store.get_stable(station_id)
        return {
            "station_id": station_id,
            "stable_bundle": stable["bundle_id"] if stable else None,
            "pipeline": (
                {
                    "bundle_id": pipeline["bundle_id"],
                    "phase": pipeline["phase"],
                    "since": pipeline["since"],
                    "executor": pipeline["executor"],
                    "prev_bundle_id": pipeline["prev_bundle_id"],
                }
                if pipeline
                else None
            ),
        }

    def is_frozen(self, bundle_id: str) -> bool:
        row = self.store.get_rollout(bundle_id)
        return bool(row and row["frozen"])
