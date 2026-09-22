"""模型放行平台服务层。

所有状态变更在单个 IMMEDIATE 事务内提交；进程重启后从
station_state/stage_history 重建视图，因此一座工位在任一时刻
只可能属于一个发布阶段，未验签的模型也无法进入发放路径。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterator

from .crypto import RsaPublicKey, SignatureError
from .domain import (
    Bundle,
    DomainError,
    ModelRecord,
    Receipt,
    RecipeRecord,
    Release,
    Sample,
    Stage,
    Thresholds,
    b64e,
    bundle_fingerprint,
    canonical_json,
    evaluate,
    evaluate_gate,
    fmt_ts,
    parse_ts,
    safety_breaches,
    validate_receipt,
)
from .store import Store


class DuplicateReceipt(DomainError):
    """回执已处理过；按幂等返回，不重复计数。"""

    def __init__(self, receipt_id: str) -> None:
        super().__init__(f"重复回执 {receipt_id}，只计一次")
        self.receipt_id = receipt_id


@dataclass(frozen=True)
class IngestResult:
    receipt_id: str
    status: str               # counted | duplicate | sealed_supplement
    bundle_id: str
    release_id: str | None
    stage: str
    samples_added: int
    frozen: bool = False
    freeze_reasons: tuple[str, ...] = ()
    rolled_back_stations: tuple[str, ...] = ()


@dataclass(frozen=True)
class ServingGrant:
    """发给机械臂的内容：整组构件与模型签名，缺一不发。"""

    station_id: str
    bundle_id: str
    fingerprint: str
    model_id: str
    model_digest: str
    model_signature: bytes
    key_id: str
    calib_id: str
    calib_digest: str
    recipe_id: str
    stage: Stage
    shadow_release_id: str | None = None


@dataclass(frozen=True)
class PromotionResult:
    release_id: str
    activated: bool
    station_metrics: dict[str, dict[str, Any]]
    reasons: tuple[str, ...] = ()
    rolled_back_stations: tuple[str, ...] = ()


class ReleasePlatform:
    def __init__(
        self,
        store: Store,
        *,
        clock: Callable[[], datetime] | None = None,
        min_shadow_samples: int = 1,
        late_window_seconds: int = 86400,
    ) -> None:
        self.store = store
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.min_shadow_samples = min_shadow_samples
        self.late_window_seconds = late_window_seconds

    def _now(self) -> datetime:
        return self.clock().astimezone(timezone.utc)

    @contextmanager
    def _tx(self) -> Iterator[None]:
        with self.store.lock:
            with self.store.transaction():
                yield

    def _audit(self, actor: str, action: str, detail: dict[str, Any], now: datetime) -> None:
        self.store.audit(actor, action, detail, fmt_ts(now))

    # --- 信任根与资产登记 ------------------------------------------------

    def register_key(self, key_id: str, key: RsaPublicKey) -> None:
        with self._tx():
            now = self._now()
            try:
                self.store.execute(
                    "INSERT INTO signing_keys(key_id, jwk_json, created_at) VALUES (?,?,?)",
                    (key_id, json.dumps(key.to_jwk(), sort_keys=True), fmt_ts(now)),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError(f"公钥 {key_id} 已存在") from exc
            self._audit("system", "key_registered", {"key_id": key_id}, now)

    def _key(self, key_id: str) -> RsaPublicKey:
        row = self.store.query_one(
            "SELECT jwk_json FROM signing_keys WHERE key_id=?", (key_id,)
        )
        if row is None:
            raise DomainError(f"未知签名公钥：{key_id}")
        return RsaPublicKey.from_jwk(json.loads(row["jwk_json"]))

    def register_model(
        self,
        model_id: str,
        digest: str,
        signature: bytes,
        key_id: str,
        *,
        created_by: str,
        artifact: bytes | None = None,
    ) -> ModelRecord:
        if not digest.startswith("sha256:"):
            raise DomainError("模型摘要必须是 sha256:<hex>")
        if artifact is not None:
            from .crypto import sha256_bytes

            actual = sha256_bytes(artifact)
            if actual != digest:
                raise DomainError(f"模型摘要不匹配：登记 {digest}，实算 {actual}")
        key = self._key(key_id)
        record = ModelRecord(model_id=model_id, digest=digest,
                             signature=signature, key_id=key_id)
        try:
            key.verify(record.signing_message(), signature)
        except SignatureError:
            raise
        with self._tx():
            now = self._now()
            try:
                self.store.execute(
                    """INSERT INTO models
                       (model_id, digest, signature, key_id, created_by, created_at)
                       VALUES (?,?,?,?,?,?)""",
                    (model_id, digest, b64e(signature), key_id, created_by, fmt_ts(now)),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError(f"模型 {model_id} 已存在") from exc
            self._audit(created_by, "model_registered",
                        {"model_id": model_id, "digest": digest, "key_id": key_id}, now)
        return record

    def register_calibration(
        self,
        calib_id: str,
        station_id: str,
        digest: str,
        *,
        created_by: str,
        signature: bytes | None = None,
        key_id: str | None = None,
    ) -> None:
        if signature is not None:
            if key_id is None:
                raise DomainError("标定签名必须给出 key_id")
            message = canonical_json(["calib@v1", calib_id, station_id, digest])
            self._key(key_id).verify(message, signature)
        with self._tx():
            now = self._now()
            try:
                self.store.execute(
                    """INSERT INTO calibrations
                       (calib_id, station_id, digest, signature, key_id, created_at)
                       VALUES (?,?,?,?,?,?)""",
                    (calib_id, station_id, digest,
                     b64e(signature) if signature else None, key_id, fmt_ts(now)),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError(f"标定 {calib_id} 已存在") from exc
            self._audit(created_by, "calibration_registered",
                        {"calib_id": calib_id, "station_id": station_id}, now)

    def register_recipe(self, recipe_id: str, thresholds: Thresholds, *, created_by: str) -> RecipeRecord:
        if thresholds.recipe_id != recipe_id:
            raise DomainError("门槛中的 recipe_id 与登记值不一致")
        thresholds.validate()
        digest = "sha256:" + hashlib.sha256(
            canonical_json(
                ["recipe@v1", recipe_id, thresholds.__dict__]
            )
        ).hexdigest()
        with self._tx():
            now = self._now()
            try:
                self.store.execute(
                    """INSERT INTO recipes(recipe_id, digest, thresholds_json, created_at)
                       VALUES (?,?,?,?)""",
                    (recipe_id, digest,
                     json.dumps({k: v for k, v in thresholds.__dict__.items()
                                 if k != "recipe_id"}, sort_keys=True),
                     fmt_ts(now)),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError(f"配方 {recipe_id} 已存在") from exc
            self._audit(created_by, "recipe_registered", {"recipe_id": recipe_id}, now)
        return RecipeRecord(recipe_id=recipe_id, digest=digest, thresholds=thresholds)

    # --- 发布组合（不可拆分的模型 + 标定 + 配方） -------------------------

    def create_bundle(
        self,
        bundle_id: str,
        model_id: str,
        recipe_id: str,
        calibs: dict[str, str],
        *,
        created_by: str,
    ) -> Bundle:
        if not calibs:
            raise DomainError("发布组合必须至少绑定一个工位的标定")
        model = self.store.get_model(model_id)
        if model is None:
            raise DomainError(f"模型 {model_id} 不存在")
        # 入库前再次验签：公钥轮换或撤销后旧签名不再可信。
        self._key(model.key_id).verify(model.signing_message(), model.signature)
        recipe = self.store.get_recipe(recipe_id)
        if recipe is None:
            raise DomainError(f"配方 {recipe_id} 不存在")
        calib_records: dict[str, Any] = {}
        for station_id, calib_id in calibs.items():
            calib = self.store.get_calibration(calib_id)
            if calib is None:
                raise DomainError(f"标定 {calib_id} 不存在")
            if calib.station_id != station_id:
                raise DomainError(f"标定 {calib_id} 不属于工位 {station_id}")
            calib_records[station_id] = calib
        fingerprint = bundle_fingerprint(model, recipe, calib_records)
        with self._tx():
            now = self._now()
            try:
                self.store.execute(
                    """INSERT INTO bundles
                       (bundle_id, fingerprint, model_id, recipe_id, created_by, created_at)
                       VALUES (?,?,?,?,?,?)""",
                    (bundle_id, fingerprint, model_id, recipe_id, created_by, fmt_ts(now)),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError(f"组合 {bundle_id} 已存在") from exc
            for station_id, calib_id in sorted(calibs.items()):
                self.store.execute(
                    "INSERT INTO bundle_calibs(bundle_id, station_id, calib_id) VALUES (?,?,?)",
                    (bundle_id, station_id, calib_id),
                )
            self._audit(created_by, "bundle_created",
                        {"bundle_id": bundle_id, "fingerprint": fingerprint,
                         "model_id": model_id, "recipe_id": recipe_id,
                         "stations": sorted(calibs)}, now)
        return Bundle(bundle_id, model_id, recipe_id, dict(calibs), created_by, now)

    # --- 发布与审批 ------------------------------------------------------

    def create_release(
        self, release_id: str, bundle_id: str, stations: list[str] | tuple[str, ...],
        *, created_by: str,
    ) -> Release:
        bundle = self.store.get_bundle(bundle_id)
        if bundle is None:
            raise DomainError(f"组合 {bundle_id} 不存在")
        stations = tuple(stations)
        if not stations:
            raise DomainError("发布必须覆盖至少一个工位")
        if len(set(stations)) != len(stations):
            raise DomainError("工位列表重复")
        missing = [s for s in stations if s not in bundle.calibs]
        if missing:
            raise DomainError("组合缺少工位标定：" + "、".join(sorted(missing)))
        with self._tx():
            now = self._now()
            try:
                self.store.execute(
                    """INSERT INTO releases
                       (release_id, bundle_id, stations_json, created_by, created_at)
                       VALUES (?,?,?,?,?)""",
                    (release_id, bundle_id, json.dumps(list(stations)),
                     created_by, fmt_ts(now)),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError(f"发布 {release_id} 已存在") from exc
            self._audit(created_by, "release_created",
                        {"release_id": release_id, "bundle_id": bundle_id,
                         "stations": list(stations)}, now)
        release = self.store.get_release(release_id)
        assert release is not None
        return release

    def approve_release(self, release_id: str, *, approver: str) -> Release:
        with self._tx():
            release = self.store.get_release(release_id)
            if release is None:
                raise DomainError(f"发布 {release_id} 不存在")
            if release.approved_by is not None:
                raise DomainError("发布已审批，不能重复审批")
            if not approver.strip() or approver == release.created_by:
                raise DomainError("审批人与发布创建人不能是同一人（职责分离）")
            now = self._now()
            self.store.execute(
                "UPDATE releases SET approved_by=?, approved_at=? WHERE release_id=?",
                (approver, fmt_ts(now), release_id),
            )
            self._audit(approver, "release_approved",
                        {"release_id": release_id}, now)
        result = self.store.get_release(release_id)
        assert result is not None
        return result

    def _require_approved(self, release: Release) -> None:
        if release.approved_by is None:
            raise DomainError("发布尚未审批")
        if release.frozen:
            raise DomainError(f"发布已冻结：{release.freeze_reason}")

    # --- 影子比对 --------------------------------------------------------

    def start_shadow(self, release_id: str, station_id: str, *, actor: str) -> None:
        with self._tx():
            release = self.store.get_release(release_id)
            if release is None or station_id not in release.stations:
                raise DomainError(f"发布 {release_id} 不含工位 {station_id}")
            self._require_approved(release)
            state = self.store.get_station_state(station_id)
            if state is not None and state.release_id == release_id:
                raise DomainError(f"工位 {station_id} 已在该发布流程中")
            now = self._now()
            history_id = self.store.open_interval(
                station_id, release_id, release.bundle_id, Stage.SHADOW, False, fmt_ts(now)
            )
            self.store.upsert_state(
                station_id, release_id, release.bundle_id, Stage.SHADOW, False,
                fmt_ts(now), history_id,
            )
            self._audit(actor, "shadow_started",
                        {"release_id": release_id, "station_id": station_id}, now)

    def record_shadow(
        self, release_id: str, station_id: str, sample_id: str, *,
        is_defect: bool, incumbent_reject: bool, candidate_reject: bool,
        latency_ms: float,
    ) -> None:
        release = self.store.get_release(release_id)
        if release is None or station_id not in release.stations:
            raise DomainError("影子观测的发布/工位不存在")
        if latency_ms < 0:
            raise DomainError("推理时延不能为负")
        with self._tx():
            try:
                self.store.execute(
                    """INSERT INTO shadow_observations
                       (release_id, station_id, sample_id, is_defect,
                        incumbent_reject, candidate_reject, latency_ms)
                       VALUES (?,?,?,?,?,?,?)""",
                    (release_id, station_id, sample_id, int(is_defect),
                     int(incumbent_reject), int(candidate_reject), latency_ms),
                )
            except sqlite3.IntegrityError:
                pass  # 同一样本重复上报，幂等忽略

    def shadow_divergence(self, release_id: str, station_id: str) -> dict[str, float | int | None]:
        rows = self.store.query(
            """SELECT incumbent_reject, candidate_reject FROM shadow_observations
               WHERE release_id=? AND station_id=?""",
            (release_id, station_id),
        )
        pairs = [(bool(r["incumbent_reject"]), bool(r["candidate_reject"])) for r in rows]
        from .domain import compare_shadow

        comp = compare_shadow(pairs)
        return {"pairs": comp.pairs, "disagreements": comp.disagreements,
                "divergence_rate": comp.divergence_rate}

    # --- 限量试运行 ------------------------------------------------------

    def start_canary(self, release_id: str, station_id: str, *, operator: str) -> None:
        with self._tx():
            release = self.store.get_release(release_id)
            if release is None or station_id not in release.stations:
                raise DomainError(f"发布 {release_id} 不含工位 {station_id}")
            self._require_approved(release)
            if operator == release.approved_by:
                raise DomainError("执行人员与审批人不能是同一人（职责分离）")
            state = self.store.get_station_state(station_id)
            if state is None or state.release_id != release_id \
                    or state.stage != Stage.SHADOW:
                raise DomainError(f"工位 {station_id} 须先完成影子比对")
            divergence = self.shadow_divergence(release_id, station_id)
            if divergence["pairs"] < self.min_shadow_samples:
                raise DomainError("影子比对样本不足，不能进入限量试运行")
            now = self._now()
            history_id = self.store.open_interval(
                station_id, release_id, release.bundle_id, Stage.CANARY, False, fmt_ts(now)
            )
            self.store.upsert_state(
                station_id, release_id, release.bundle_id, Stage.CANARY, False,
                fmt_ts(now), history_id,
            )
            self._audit(operator, "canary_started",
                        {"release_id": release_id, "station_id": station_id,
                         "shadow": divergence}, now)

    def confirm_station(self, release_id: str, station_id: str, *, operator: str) -> None:
        """现场执行人员确认工位已按新组合作业。"""

        with self._tx():
            state = self.store.get_station_state(station_id)
            if state is None or state.release_id != release_id:
                raise DomainError("工位不属于该发布")
            if state.stage not in (Stage.CANARY, Stage.ACTIVE):
                raise DomainError("影子阶段无需现场确认")
            release = self.store.get_release(release_id)
            assert release is not None
            if operator == release.approved_by:
                raise DomainError("确认人员与审批人不能是同一人（职责分离）")
            row = self.store.query_one(
                """SELECT id FROM stage_history
                   WHERE station_id=? AND release_id=? AND ended_at IS NULL""",
                (station_id, release_id),
            )
            if row is None:
                raise DomainError("工位没有进行中的发布区间")
            self.store.mark_confirmed(station_id, row["id"])
            now = self._now()
            self._audit(operator, "station_confirmed",
                        {"release_id": release_id, "station_id": station_id}, now)

    def confirm_restored(self, station_id: str, *, operator: str) -> None:
        """回滚后现场确认工位已恢复到上一稳定组合。"""

        with self._tx():
            state = self.store.get_station_state(station_id)
            if state is None or state.stage is not Stage.ACTIVE \
                    or state.release_id is not None or state.confirmed:
                raise DomainError("工位没有待确认的恢复区间")
            row = self.store.query_one(
                """SELECT id FROM stage_history
                   WHERE station_id=? AND release_id IS NULL AND ended_at IS NULL""",
                (station_id,),
            )
            if row is None:
                raise DomainError("工位没有进行中的恢复区间")
            self.store.mark_confirmed(station_id, row["id"])
            now = self._now()
            self._audit(operator, "restored_confirmed",
                        {"station_id": station_id,
                         "bundle_id": state.bundle_id}, now)

    # --- 回执接入：归属、去重、封存、越界冻结 -----------------------------

    def _attribute(self, receipt: Receipt) -> tuple[str, str | None, Stage, bool]:
        """返回 (release_id, stage, attributed, late)。

        归属以执行时刻 occurred_at 对应的工位历史区间为准，而非接收顺序；
        断网重连时区间虽已关闭，只要执行时刻落在该组合的在役/试运行区间，
        或该组合是执行时刻之前最近执行过的在役组合（影子期的在役模型），
        仍归入实际执行过的组合。回滚生效后产生的候选组合回执一律拒绝。
        """

        when = fmt_ts(receipt.occurred_at)
        row = self.store.interval_at(receipt.station_id, when)
        if row is not None and row["bundle_id"] == receipt.bundle_id:
            if Stage(row["stage"]) is Stage.ROLLED_BACK:
                return None, Stage.SHADOW, False, False
            return row["release_id"], Stage(row["stage"]), True, False
        # 当前区间属于另一个组合：可能是影子期在役模型的正常生产回执。
        if row is not None and Stage(row["stage"]) is Stage.SHADOW:
            rows = self.store.query(
                """SELECT * FROM stage_history
                   WHERE station_id=? AND bundle_id=? AND stage='active'
                     AND ended_at=?
                   ORDER BY started_at DESC LIMIT 1""",
                (receipt.station_id, receipt.bundle_id, row["started_at"]),
            )
            if rows:
                return rows[0]["release_id"], Stage.ACTIVE, True, False
        # 断网迟到：执行时刻之前最近一条该组合的可执行（限量/在役）区间，
        # 且执行时刻距离区间结束不超过离线宽限窗口。
        rows = self.store.query(
            """SELECT * FROM stage_history
               WHERE station_id=? AND bundle_id=? AND stage IN ('canary','active')
                 AND started_at<=?
               ORDER BY started_at DESC LIMIT 1""",
            (receipt.station_id, receipt.bundle_id, when),
        )
        if rows:
            ended = rows[0]["ended_at"]
            if ended is not None:
                grace = (receipt.occurred_at - parse_ts(ended)).total_seconds()
                if 0 <= grace <= self.late_window_seconds:
                    # 区间结束后若已发生回滚，执行时刻不可能仍是候选组合。
                    blocked = self.store.query_one(
                        """SELECT 1 FROM stage_history
                           WHERE station_id=? AND bundle_id=?
                             AND stage='rolled_back' AND started_at<=?
                           LIMIT 1""",
                        (receipt.station_id, receipt.bundle_id, when),
                    )
                    if blocked is None:
                        return rows[0]["release_id"], Stage(rows[0]["stage"]), True, True
        return None, Stage.SHADOW, False, False

    def ingest_receipt(self, receipt: Receipt) -> IngestResult:
        validate_receipt(receipt)
        if receipt.signature is not None:
            assert receipt.key_id is not None
            try:
                self._key(receipt.key_id).verify(
                    receipt.signing_message(), receipt.signature
                )
            except SignatureError:
                raise
        with self._tx():
            duplicate = self.store.query_one(
                "SELECT receipt_id FROM receipts WHERE receipt_id=?",
                (receipt.receipt_id,),
            )
            if duplicate is not None:
                # 整个事务内未写入任何样本，抛出由调用方按幂等处理。
                raise DuplicateReceipt(receipt.receipt_id)

            release_id, stage, attributed, late = self._attribute(receipt)
            if not attributed:
                raise DomainError(
                    f"回执 {receipt.receipt_id} 声称的组合 {receipt.bundle_id} "
                    f"从未在工位 {receipt.station_id} 执行过，拒绝归属"
                )
            release = self.store.get_release(release_id) if release_id else None
            recipe = (
                self.store.get_recipe(self.store.get_bundle(release.bundle_id).recipe_id)
                if release is not None else None
            )
            now = self._now()

            # 已封存批次：只登记补充证据，绝不改封存统计。
            sealed = None
            if receipt.batch_id is not None:
                sealed = self.store.get_seal(receipt.batch_id)
            if sealed is not None:
                self.store.execute(
                    """INSERT INTO batch_supplements
                       (batch_id, receipt_id, station_id, bundle_id, sample_count,
                        occurred_at, received_at)
                       VALUES (?,?,?,?,?,?,?)""",
                    (receipt.batch_id, receipt.receipt_id, receipt.station_id,
                     receipt.bundle_id, len(receipt.samples),
                     fmt_ts(receipt.occurred_at), fmt_ts(receipt.received_at)),
                )
                self.store.execute(
                    """INSERT INTO receipts
                       (receipt_id, station_id, bundle_id, stage, occurred_at,
                        received_at, batch_id, key_id, signature, sealed_batch, is_late)
                       VALUES (?,?,?,?,?,?,?,?,?,1,?)""",
                    (receipt.receipt_id, receipt.station_id, receipt.bundle_id,
                     stage.value, fmt_ts(receipt.occurred_at),
                     fmt_ts(receipt.received_at), receipt.batch_id,
                     receipt.key_id,
                     b64e(receipt.signature) if receipt.signature else None,
                     1 if late else 0),
                )
                self._audit("station:" + receipt.station_id, "late_receipt_supplement",
                            {"receipt_id": receipt.receipt_id,
                             "batch_id": receipt.batch_id, "late": late}, now)
                return IngestResult(
                    receipt_id=receipt.receipt_id, status="sealed_supplement",
                    bundle_id=receipt.bundle_id, release_id=release_id,
                    stage=stage.value, samples_added=0,
                )

            # 限量上限：超出 canary_cap 的样本拒绝计入，避免继续暴露。
            if stage == Stage.CANARY and recipe is not None:
                count_row = self.store.query_one(
                    "SELECT COUNT(*) AS c FROM samples WHERE station_id=? AND bundle_id=? AND stage='canary'",
                    (receipt.station_id, receipt.bundle_id),
                )
                if count_row["c"] + len(receipt.samples) > recipe.thresholds.canary_cap:
                    raise DomainError(
                        f"工位 {receipt.station_id} 限量试运行件数上限 "
                        f"{recipe.thresholds.canary_cap}，拒绝继续计入"
                    )

            self.store.execute(
                """INSERT INTO receipts
                   (receipt_id, station_id, bundle_id, stage, occurred_at,
                    received_at, batch_id, key_id, signature, sealed_batch, is_late)
                   VALUES (?,?,?,?,?,?,?,?,?,0,?)""",
                (receipt.receipt_id, receipt.station_id, receipt.bundle_id,
                 stage.value, fmt_ts(receipt.occurred_at),
                 fmt_ts(receipt.received_at), receipt.batch_id, receipt.key_id,
                 b64e(receipt.signature) if receipt.signature else None,
                 1 if late else 0),
            )
            for item in receipt.samples:
                self.store.execute(
                    """INSERT INTO samples
                       (receipt_id, station_id, bundle_id, batch_id, stage,
                        sample_id, is_defect, model_reject, latency_ms,
                        occurred_at, received_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (receipt.receipt_id, receipt.station_id, receipt.bundle_id,
                     receipt.batch_id, stage.value, item.sample_id,
                     int(item.is_defect), int(item.model_reject), item.latency_ms,
                     fmt_ts(receipt.occurred_at), fmt_ts(receipt.received_at)),
                )
            self._audit("station:" + receipt.station_id, "receipt_ingested",
                        {"receipt_id": receipt.receipt_id, "bundle_id": receipt.bundle_id,
                         "stage": stage.value, "late": late,
                         "samples": len(receipt.samples)}, now)

            frozen = False
            reasons: tuple[str, ...] = ()
            rolled_back: tuple[str, ...] = ()
            if (
                stage in (Stage.CANARY, Stage.ACTIVE)
                and release is not None
                and recipe is not None
                and not release.frozen
            ):
                # 限量与扩围阶段持续做安全监控，样本一到即判越界。
                monitored = (
                    self._release_samples(release, receipt.station_id, Stage.CANARY)
                    + self._release_samples(release, receipt.station_id, Stage.ACTIVE)
                )
                breach = safety_breaches(monitored, recipe.thresholds)
                if breach:
                    rolled_back = self._freeze_and_rollback(
                        release, receipt.station_id, receipt.receipt_id,
                        tuple(breach), evaluate(monitored).to_dict(), now,
                    )
                    frozen, reasons = True, tuple(breach)

            return IngestResult(
                receipt_id=receipt.receipt_id, status="counted",
                bundle_id=receipt.bundle_id, release_id=release_id,
                stage=stage.value, samples_added=len(receipt.samples),
                frozen=frozen, freeze_reasons=reasons,
                rolled_back_stations=rolled_back,
            )

    def _release_samples(self, release: Release, station_id: str,
                         stage: Stage) -> list[Sample]:
        rows = self.store.query(
            """SELECT * FROM samples
               WHERE station_id=? AND bundle_id=? AND stage=?
               ORDER BY occurred_at, id""",
            (station_id, release.bundle_id, stage.value),
        )
        return [self._sample_from_row(r) for r in rows]

    def _canary_samples(self, release: Release, station_id: str) -> list[Sample]:
        return self._release_samples(release, station_id, Stage.CANARY)

    @staticmethod
    def _sample_from_row(row: sqlite3.Row) -> Sample:
        return Sample(
            station_id=row["station_id"], bundle_id=row["bundle_id"],
            batch_id=row["batch_id"], receipt_id=row["receipt_id"],
            sample_id=row["sample_id"], is_defect=bool(row["is_defect"]),
            model_reject=bool(row["model_reject"]), latency_ms=row["latency_ms"],
            occurred_at=parse_ts(row["occurred_at"]),
            received_at=parse_ts(row["received_at"]),
        )

    # --- 冻结与回滚 ------------------------------------------------------

    def _previous_stable(self, station_id: str, before: datetime,
                         candidate_bundle: str) -> str | None:
        row = self.store.query_one(
            """SELECT bundle_id FROM stage_history
               WHERE station_id=? AND stage='active' AND bundle_id!=?
                 AND started_at<=?
               ORDER BY started_at DESC LIMIT 1""",
            (station_id, candidate_bundle, fmt_ts(before)),
        )
        return row["bundle_id"] if row else None

    def _freeze_and_rollback(
        self, release: Release, trigger_station: str, receipt_id: str,
        reasons: tuple[str, ...], metrics: dict[str, Any], now: datetime,
    ) -> tuple[str, ...]:
        """冻结扩围，未确认工位退回上一稳定组合。必须在事务内调用。"""

        self.store.execute(
            "UPDATE releases SET frozen=1, freeze_reason=? WHERE release_id=?",
            ("；".join(reasons), release.release_id),
        )
        self.store.execute(
            """INSERT INTO rollback_evidence
               (release_id, station_id, receipt_id, reasons_json, metrics_json, triggered_at)
               VALUES (?,?,?,?,?,?)""",
            (release.release_id, trigger_station, receipt_id,
             json.dumps(list(reasons), ensure_ascii=False),
             json.dumps(metrics, sort_keys=True), fmt_ts(now)),
        )
        rolled_back: list[str] = []
        for station_id in release.stations:
            state = self.store.get_station_state(station_id)
            if state is None or state.release_id != release.release_id:
                continue
            if state.confirmed:
                continue  # 已现场确认的工位保留，但冻结使任何扩围停止。
            previous = self._previous_stable(station_id, now, release.bundle_id)
            history_id = self.store.open_interval(
                station_id,
                release.release_id,
                release.bundle_id,
                Stage.ROLLED_BACK,
                False,
                fmt_ts(now),
            )
            self.store.upsert_state(
                station_id, release.release_id, release.bundle_id, Stage.ROLLED_BACK,
                False, fmt_ts(now), history_id,
            )
            if previous is not None:
                restore_id = self.store.open_interval(
                    station_id, None, previous, Stage.ACTIVE, False,
                    fmt_ts(now),
                )
                self.store.upsert_state(
                    station_id, None, previous, Stage.ACTIVE, False,
                    fmt_ts(now), restore_id,
                )
            rolled_back.append(station_id)
        self._audit("system", "release_frozen_rollback",
                    {"release_id": release.release_id,
                     "trigger_station": trigger_station, "receipt_id": receipt_id,
                     "reasons": list(reasons), "rolled_back": rolled_back}, now)
        return tuple(rolled_back)

    def freeze(self, release_id: str, *, actor: str, reason: str) -> None:
        """人工冻结。"""

        with self._tx():
            release = self.store.get_release(release_id)
            if release is None:
                raise DomainError(f"发布 {release_id} 不存在")
            if release.frozen:
                raise DomainError("发布已处于冻结状态")
            now = self._now()
            self.store.execute(
                "UPDATE releases SET frozen=1, freeze_reason=? WHERE release_id=?",
                (reason, release_id),
            )
            self._audit(actor, "release_frozen",
                        {"release_id": release_id, "reason": reason}, now)

    # --- 扩围判定 --------------------------------------------------------

    def canary_metrics(self, release_id: str) -> dict[str, dict[str, Any]]:
        release = self.store.get_release(release_id)
        if release is None:
            raise DomainError(f"发布 {release_id} 不存在")
        bundle = self.store.get_bundle(release.bundle_id)
        assert bundle is not None
        recipe = self.store.get_recipe(bundle.recipe_id)
        assert recipe is not None
        result: dict[str, dict[str, Any]] = {}
        for station_id in release.stations:
            metrics = evaluate(self._canary_samples(release, station_id))
            result[station_id] = metrics.to_dict()
        return result

    def promote(self, release_id: str) -> PromotionResult:
        """三工位门槛全部通过才允许扩围。

        - 证据不足（未现场确认、样本量不够）：拒绝扩围，工位继续限量观察，
          不触发回滚；
        - 任一安全指标实际越界：冻结扩围并退回未确认工位。
        """

        with self._tx():
            release = self.store.get_release(release_id)
            if release is None:
                raise DomainError(f"发布 {release_id} 不存在")
            if release.frozen:
                raise DomainError(f"发布已冻结：{release.freeze_reason}")
            bundle = self.store.get_bundle(release.bundle_id)
            assert bundle is not None
            recipe = self.store.get_recipe(bundle.recipe_id)
            assert recipe is not None
            now = self._now()

            pending: list[str] = []
            breaches: list[str] = []
            station_metrics: dict[str, dict[str, Any]] = {}
            for station_id in release.stations:
                state = self.store.get_station_state(station_id)
                if state is None or state.release_id != release_id \
                        or state.stage != Stage.CANARY or not state.confirmed:
                    pending.append(f"工位 {station_id} 尚未完成现场确认的限量试运行")
                samples = self._canary_samples(release, station_id)
                verdict = evaluate_gate(samples, recipe.thresholds)
                station_metrics[station_id] = verdict.metrics
                actual = safety_breaches(samples, recipe.thresholds)
                if actual:
                    breaches.extend(f"[{station_id}] {r}" for r in actual)
                elif not verdict.passed:
                    # 无越界但门槛未齐（样本量不足/缺缺陷或良品样本）：继续观察。
                    pending.extend(
                        f"[{station_id}] {r}"
                        for r in verdict.reasons if r not in actual
                    )

            if breaches:
                rolled = self._freeze_and_rollback(
                    release, "(promotion-gate)", "(promotion-gate)",
                    tuple(breaches), station_metrics, now,
                )
                return PromotionResult(
                    release_id=release_id, activated=False,
                    station_metrics=station_metrics, reasons=tuple(breaches),
                    rolled_back_stations=rolled,
                )
            if pending:
                return PromotionResult(
                    release_id=release_id, activated=False,
                    station_metrics=station_metrics, reasons=tuple(pending),
                )

            for station_id in release.stations:
                history_id = self.store.open_interval(
                    station_id, release.release_id, release.bundle_id,
                    Stage.ACTIVE, True, fmt_ts(now),
                )
                self.store.upsert_state(
                    station_id, release_id, release.bundle_id, Stage.ACTIVE, True,
                    fmt_ts(now), history_id,
                )
            self._audit("system", "release_activated",
                        {"release_id": release_id,
                         "metrics": station_metrics}, now)
            return PromotionResult(
                release_id=release_id, activated=True,
                station_metrics=station_metrics,
            )

    # --- 机械臂取模型：只发签名、只发当前唯一阶段 --------------------------

    def provision_stable(self, station_id: str, bundle_id: str, *, actor: str) -> None:
        """登记工位当前在役的稳定组合（基线）。"""

        bundle = self.store.get_bundle(bundle_id)
        if bundle is None:
            raise DomainError(f"组合 {bundle_id} 不存在")
        if station_id not in bundle.calibs:
            raise DomainError(f"组合 {bundle_id} 未绑定工位 {station_id}")
        state = self.store.get_station_state(station_id)
        if state is not None and state.stage in (Stage.CANARY, Stage.ACTIVE):
            raise DomainError("工位已有在役组合，不能重复上线基线")
        with self._tx():
            now = self._now()
            history_id = self.store.open_interval(
                station_id, None, bundle_id, Stage.ACTIVE, True, fmt_ts(now)
            )
            self.store.upsert_state(
                station_id, None, bundle_id, Stage.ACTIVE, True,
                fmt_ts(now), history_id,
            )
            self._audit(actor, "stable_provisioned",
                        {"station_id": station_id, "bundle_id": bundle_id}, now)

    def _grant_for(self, station_id: str, bundle_id: str, stage: Stage,
                   shadow_release_id: str | None) -> ServingGrant:
        bundle = self.store.get_bundle(bundle_id)
        if bundle is None:
            raise DomainError(f"组合 {bundle_id} 已不存在")
        model = self.store.get_model(bundle.model_id)
        recipe = self.store.get_recipe(bundle.recipe_id)
        if model is None or recipe is None:
            raise DomainError("组合构件缺失")
        if not model.signature:
            raise DomainError("模型缺少签名，拒绝发放")  # 双保险
        self._key(model.key_id).verify(model.signing_message(), model.signature)
        calib_id = bundle.calib_for(station_id)
        calib = self.store.get_calibration(calib_id)
        assert calib is not None
        fingerprint = self.store.bundle_fingerprint(bundle.bundle_id)
        assert fingerprint
        return ServingGrant(
            station_id=station_id, bundle_id=bundle.bundle_id,
            fingerprint=fingerprint, model_id=model.model_id,
            model_digest=model.digest, model_signature=model.signature,
            key_id=model.key_id, calib_id=calib.calib_id,
            calib_digest=calib.digest, recipe_id=recipe.recipe_id,
            stage=stage, shadow_release_id=shadow_release_id,
        )

    def serving_grant(self, station_id: str) -> ServingGrant | None:
        """返回当前唯一允许发给机械臂的整组构件。

        - 限量/在役：发放当前组合；
        - 影子：候选不外发，继续发放上一稳定组合；
        - 回滚中间态：不发放。
        """

        state = self.store.get_station_state(station_id)
        if state is None or state.bundle_id is None:
            return None
        if state.stage in (Stage.CANARY, Stage.ACTIVE):
            return self._grant_for(station_id, state.bundle_id, state.stage, None)
        if state.stage is Stage.SHADOW:
            row = self.store.query_one(
                """SELECT bundle_id FROM stage_history
                   WHERE station_id=? AND stage='active' AND started_at<=?
                   ORDER BY started_at DESC LIMIT 1""",
                (station_id, fmt_ts(state.since)),
            )
            if row is None:
                return None
            return self._grant_for(
                station_id, row["bundle_id"], Stage.ACTIVE,
                state.release_id,
            )
        return None

    # --- 批次封存 --------------------------------------------------------

    def seal_batch(self, batch_id: str, *, actor: str) -> dict[str, Any]:
        with self._tx():
            existing = self.store.get_seal(batch_id)
            if existing is not None:
                return {"batch_id": batch_id, "sealed_at": existing[0],
                        "stats": existing[1], "receipt_ids": list(existing[2]),
                        "already_sealed": True}
            rows = self.store.query(
                """SELECT * FROM receipts WHERE batch_id=? AND sealed_batch=0
                   ORDER BY occurred_at""",
                (batch_id,),
            )
            receipt_ids = [r["receipt_id"] for r in rows]
            sample_rows = self.store.query(
                "SELECT * FROM samples WHERE batch_id=? ORDER BY occurred_at, id",
                (batch_id,),
            )
            samples = [self._sample_from_row(r) for r in sample_rows]
            metrics = evaluate(samples).to_dict()
            per_station: dict[str, Any] = {}
            grouped: dict[str, list[Sample]] = defaultdict(list)
            for sample in samples:
                grouped[sample.station_id].append(sample)
            for station_id, items in sorted(grouped.items()):
                per_station[station_id] = evaluate(items).to_dict()
            stats = {"overall": metrics, "per_station": per_station}
            now = self._now()
            self.store.execute(
                "INSERT INTO batch_seals(batch_id, sealed_at, stats_json, receipt_ids_json) VALUES (?,?,?,?)",
                (batch_id, fmt_ts(now), json.dumps(stats, ensure_ascii=False, sort_keys=True),
                 json.dumps(receipt_ids)),
            )
            self.store.execute(
                "UPDATE receipts SET sealed_batch=1 WHERE batch_id=?", (batch_id,)
            )
            self._audit(actor, "batch_sealed",
                        {"batch_id": batch_id, "receipts": len(receipt_ids),
                         "samples": metrics["n"]}, now)
            return {"batch_id": batch_id, "sealed_at": fmt_ts(now), "stats": stats,
                    "receipt_ids": receipt_ids, "already_sealed": False}

    def sealed_batch(self, batch_id: str) -> dict[str, Any] | None:
        sealed = self.store.get_seal(batch_id)
        if sealed is None:
            return None
        supplements = self.store.query(
            "SELECT * FROM batch_supplements WHERE batch_id=? ORDER BY id",
            (batch_id,),
        )
        return {
            "batch_id": batch_id,
            "sealed_at": sealed[0],
            "stats": sealed[1],
            "receipt_ids": list(sealed[2]),
            "late_supplements": [
                {"receipt_id": r["receipt_id"], "station_id": r["station_id"],
                 "bundle_id": r["bundle_id"], "sample_count": r["sample_count"],
                 "occurred_at": r["occurred_at"], "received_at": r["received_at"]}
                for r in supplements
            ],
        }
