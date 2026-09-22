"""放行平台端到端规则测试。"""

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from arm_release.crypto import generate_rsa
from arm_release.domain import (
    DomainError,
    Receipt,
    SampleInput,
    Stage,
    Thresholds,
    b64e,
    canonical_json,
    parse_ts,
)
from arm_release.service import DuplicateReceipt, ReleasePlatform
from arm_release.store import Store

STATIONS = ["arm-cell-01", "arm-cell-02", "arm-cell-03"]
T0 = datetime(2026, 9, 10, 8, 0, tzinfo=timezone(timedelta(hours=8)))


class Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value

    def advance(self, minutes: int) -> None:
        self.value += timedelta(minutes=minutes)


def bootstrap(store: Store, clock: Clock):
    """在给定库中注册完整测试资产并返回 (平台, 签名私钥)。"""

    key = generate_rsa(1024)  # 测试用小模数，速度优先
    pf = ReleasePlatform(store, clock=clock)
    pf.register_key("k1", key.public)
    th = Thresholds(
        recipe_id="R", min_recall=0.95, max_false_reject_rate=0.02,
        max_latency_ms=120.0, min_decision_samples=20, canary_cap=40,
    )
    import hashlib

    for model_id, payload in (("m-old", b"old"), ("m-new", b"new")):
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        msg = canonical_json(["model@v1", model_id, digest])
        pf.register_model(model_id, digest, key.sign(msg), "k1", created_by="ml-eng")
    for station in STATIONS:
        for suffix in ("", "-v2"):
            pf.register_calibration(
                f"cal{station[-2:]}{suffix}", station,
                f"sha256:{station}{suffix}", created_by="optics",
            )
    pf.register_recipe("R", th, created_by="quality")
    pf.create_bundle(
        "B-old", "m-old", "R",
        {s: f"cal{s[-2:]}" for s in STATIONS}, created_by="eng.zhao",
    )
    pf.create_bundle(
        "B-new", "m-new", "R",
        {s: f"cal{s[-2:]}-v2" for s in STATIONS}, created_by="eng.zhao",
    )
    for station in STATIONS:
        pf.provision_stable(station, "B-old", actor="lead")
    return pf, key


class PlatformTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock(T0)
        self.store = Store(":memory:")
        self.pf, self.key = bootstrap(self.store, self.clock)
        self.th = Thresholds(
            recipe_id="R", min_recall=0.95, max_false_reject_rate=0.02,
            max_latency_ms=120.0, min_decision_samples=20, canary_cap=40,
        )

    def tearDown(self) -> None:
        self.store.close()

    def _model_sig(self, model_id: str, digest: str) -> bytes:
        return self.key.sign(canonical_json(["model@v1", model_id, digest]))

    def _release(self) -> None:
        self.clock.advance(10)
        self.pf.create_release(
            "REL", "B-new", STATIONS, created_by="eng.zhao"
        )
        self.pf.approve_release("REL", approver="quality.li")
        self.clock.advance(1)
        for station in STATIONS:
            self.pf.start_shadow("REL", station, actor="lead")
        for station in STATIONS:
            for i in range(5):
                self.pf.record_shadow(
                    "REL", station, f"{station}-{i}",
                    is_defect=(i == 4), incumbent_reject=(i == 4),
                    candidate_reject=(i == 4), latency_ms=70.0,
                )
        self.clock.advance(1)
        for station in STATIONS:
            self.pf.start_canary("REL", station, operator="lead")
        self.clock.advance(1)

    def _receipt(
        self, receipt_id: str, station: str, bundle: str, samples: list,
        *, occurred: datetime, received: datetime | None = None,
        batch_id: str | None = None, sign: bool = True,
    ) -> Receipt:
        return Receipt(
            receipt_id=receipt_id, station_id=station, bundle_id=bundle,
            occurred_at=occurred, received_at=received or occurred + timedelta(minutes=1),
            samples=[SampleInput(*s) for s in samples],
            batch_id=batch_id, key_id="k1" if sign else None,
            signature=(
                self._sign_receipt(receipt_id, station, bundle, occurred,
                                   received or occurred + timedelta(minutes=1),
                                   samples, batch_id)
                if sign else None
            ),
        )

    def _sign_receipt(self, receipt_id, station, bundle, occurred, received,
                      samples, batch_id) -> bytes:
        r = Receipt(
            receipt_id=receipt_id, station_id=station, bundle_id=bundle,
            occurred_at=occurred, received_at=received,
            samples=[SampleInput(*s) for s in samples], batch_id=batch_id,
        )
        return self.key.sign(r.signing_message())

    def _healthy(self, prefix: str, n: int) -> list:
        rows = []
        for i in range(n):
            defect = i % 9 == 0
            rows.append((f"{prefix}-{i}", defect, defect, 60.0 + i))
        return rows

    # --- 信任根 ----------------------------------------------------------

    def test_unsigned_model_rejected(self) -> None:
        with self.assertRaises(Exception):
            self.pf.register_model(
                "m-bad", "sha256:" + "0" * 64, b"", "k1", created_by="x",
            )

    def test_tampered_signature_rejected(self) -> None:
        digest = "sha256:" + "a" * 64
        good = self._model_sig("m-x", digest)
        tampered = good[:-1] + bytes([good[-1] ^ 1])
        with self.assertRaises(Exception):
            self.pf.register_model("m-x", digest, tampered, "k1", created_by="x")

    def test_unknown_key_rejected(self) -> None:
        digest = "sha256:" + "b" * 64
        with self.assertRaises(DomainError):
            self.pf.register_model(
                "m-y", digest, self._model_sig("m-y", digest), "ghost",
                created_by="x",
            )

    def test_bundle_requires_all_calibs(self) -> None:
        with self.assertRaises(DomainError):
            self.pf.create_release("REL2", "B-new", ["arm-cell-99"],
                                   created_by="eng.zhao")

    # --- 职责分离 --------------------------------------------------------

    def test_approver_must_differ_from_creator(self) -> None:
        self.pf.create_release("RELx", "B-new", STATIONS, created_by="eng.zhao")
        with self.assertRaises(DomainError):
            self.pf.approve_release("RELx", approver="eng.zhao")

    def test_operator_must_differ_from_approver(self) -> None:
        self.pf.create_release("RELx", "B-new", STATIONS, created_by="eng.zhao")
        self.pf.approve_release("RELx", approver="quality.li")
        self.pf.start_shadow("RELx", STATIONS[0], actor="lead")
        for i in range(2):
            self.pf.record_shadow(
                "RELx", STATIONS[0], f"s{i}", is_defect=False,
                incumbent_reject=False, candidate_reject=False, latency_ms=50,
            )
        with self.assertRaises(DomainError):
            self.pf.start_canary("RELx", STATIONS[0], operator="quality.li")

    # --- 阶段门 ----------------------------------------------------------

    def test_shadow_must_precede_canary(self) -> None:
        self.pf.create_release("RELx", "B-new", STATIONS, created_by="eng.zhao")
        self.pf.approve_release("RELx", approver="quality.li")
        with self.assertRaises(DomainError):
            self.pf.start_canary("RELx", STATIONS[0], operator="lead")

    def test_unapproved_release_cannot_start(self) -> None:
        self.pf.create_release("RELx", "B-new", STATIONS, created_by="eng.zhao")
        with self.assertRaises(DomainError):
            self.pf.start_shadow("RELx", STATIONS[0], actor="lead")

    def test_shadow_does_not_serve_candidate(self) -> None:
        self.pf.create_release("RELx", "B-new", STATIONS, created_by="eng.zhao")
        self.pf.approve_release("RELx", approver="quality.li")
        self.pf.start_shadow("RELx", STATIONS[0], actor="lead")
        grant = self.pf.serving_grant(STATIONS[0])
        self.assertIsNotNone(grant)
        self.assertEqual(grant.bundle_id, "B-old")  # 在役仍是旧组合
        self.assertEqual(grant.shadow_release_id, "RELx")

    # --- 正常扩围 --------------------------------------------------------

    def test_full_promotion_path(self) -> None:
        self._release()
        for station in STATIONS:
            r = self._receipt(
                f"r-{station}", station, "B-new", self._healthy(station, 24),
                occurred=self.clock.value + timedelta(minutes=10),
            )
            self.pf.ingest_receipt(r)
            self.pf.confirm_station("REL", station, operator="op.zhou")
        result = self.pf.promote("REL")
        self.assertTrue(result.activated)
        for station in STATIONS:
            self.assertEqual(self.pf.serving_grant(station).stage, Stage.ACTIVE)
            self.assertEqual(self.pf.serving_grant(station).bundle_id, "B-new")

    def test_promotion_requires_decision_volume(self) -> None:
        self._release()
        for station in STATIONS:
            self.pf.ingest_receipt(self._receipt(
                f"r-{station}", station, "B-new", self._healthy(station, 5),
                occurred=self.clock.value + timedelta(minutes=10),
            ))
            self.pf.confirm_station("REL", station, operator="op.zhou")
        result = self.pf.promote("REL")
        # 证据不足：拒绝扩围但不冻结，工位继续限量观察。
        self.assertFalse(result.activated)
        self.assertFalse(self.store.get_release("REL").frozen)
        self.assertEqual(
            self.store.get_station_state(STATIONS[0]).stage, Stage.CANARY
        )

    def test_promotion_with_actual_breach_is_preempted_at_ingest(self) -> None:
        # 越界在回执接入瞬间即冻结，promote 只会看到 frozen 状态。
        self._release()
        for station in STATIONS[:2]:
            self.pf.ingest_receipt(self._receipt(
                f"r-{station}", station, "B-new", self._healthy(station, 24),
                occurred=self.clock.value + timedelta(minutes=10),
            ))
            self.pf.confirm_station("REL", station, operator="op.zhou")
        result = self.pf.ingest_receipt(self._receipt(
            "r-03", STATIONS[2], "B-new", self._bad_frr_samples(),
            occurred=self.clock.value + timedelta(minutes=11),
        ))
        self.assertTrue(result.frozen)
        with self.assertRaises(DomainError):
            self.pf.promote("REL")

    def test_promotion_requires_all_confirmed(self) -> None:
        self._release()
        for station in STATIONS:
            self.pf.ingest_receipt(self._receipt(
                f"r-{station}", station, "B-new", self._healthy(station, 24),
                occurred=self.clock.value + timedelta(minutes=10),
            ))
        self.pf.confirm_station("REL", STATIONS[0], operator="op.zhou")
        result = self.pf.promote("REL")
        self.assertFalse(result.activated)

    # --- 越界冻结与回滚 --------------------------------------------------

    def _bad_frr_samples(self, n=24) -> list:
        rows = []
        for i in range(n):
            defect = i in (3, 17)
            reject = defect or i in (1, 8)  # 2/22 良品误剔 ≈ 9%
            rows.append((f"s{i}", defect, reject, 80.0))
        return rows

    def test_canary_false_reject_breach_freezes_and_rolls_back_unconfirmed(self) -> None:
        self._release()
        self.pf.confirm_station("REL", STATIONS[0], operator="op.zhou")
        self.pf.confirm_station("REL", STATIONS[1], operator="op.zhou")
        # 01、02 健康
        for station in STATIONS[:2]:
            self.pf.ingest_receipt(self._receipt(
                f"r-{station}", station, "B-new", self._healthy(station, 24),
                occurred=self.clock.value + timedelta(minutes=10),
            ))
        # 03 越界且未确认
        result = self.pf.ingest_receipt(self._receipt(
            "r-03", STATIONS[2], "B-new", self._bad_frr_samples(),
            occurred=self.clock.value + timedelta(minutes=12),
        ))
        self.assertTrue(result.frozen)
        self.assertEqual(result.rolled_back_stations, (STATIONS[2],))
        state03 = self.store.get_station_state(STATIONS[2])
        self.assertEqual(state03.bundle_id, "B-old")
        self.assertFalse(state03.confirmed)
        # 已确认的 01、02 保持候选，但冻结阻止扩围
        self.assertEqual(self.store.get_station_state(STATIONS[0]).bundle_id, "B-new")
        with self.assertRaises(DomainError):
            self.pf.promote("REL")
        # 回滚后 03 领取的是旧组合
        self.assertEqual(self.pf.serving_grant(STATIONS[2]).bundle_id, "B-old")

    def test_latency_breach_freezes(self) -> None:
        self._release()
        slow = [(f"s{i}", False, False, 200.0) for i in range(6)]
        result = self.pf.ingest_receipt(self._receipt(
            "r-slow", STATIONS[0], "B-new", slow,
            occurred=self.clock.value + timedelta(minutes=10),
        ))
        self.assertTrue(result.frozen)
        self.assertTrue(any("时延" in r for r in result.freeze_reasons))

    def test_recall_breach_freezes(self) -> None:
        self._release()
        # 20 件含 5 件缺陷，其中 2 件漏判，召回 0.6
        rows = []
        for i in range(20):
            defect = i in (2, 5, 8, 11, 14)
            reject = defect and i not in (8, 14)
            rows.append((f"s{i}", defect, reject, 50.0))
        result = self.pf.ingest_receipt(self._receipt(
            "r-recall", STATIONS[0], "B-new", rows,
            occurred=self.clock.value + timedelta(minutes=10),
        ))
        self.assertTrue(result.frozen)
        self.assertTrue(any("召回" in r for r in result.freeze_reasons))

    def test_canary_cap_enforced(self) -> None:
        self._release()
        with self.assertRaises(DomainError):
            self.pf.ingest_receipt(self._receipt(
                "r-cap", STATIONS[0], "B-new", self._healthy("cap", 41),
                occurred=self.clock.value + timedelta(minutes=10),
            ))

    # --- 回执：幂等、迟到、冒名 ------------------------------------------

    def test_duplicate_receipt_counts_once(self) -> None:
        self._release()
        r = self._receipt(
            "rdup", STATIONS[0], "B-new", self._healthy("d", 10),
            occurred=self.clock.value + timedelta(minutes=10),
        )
        first = self.pf.ingest_receipt(r)
        self.assertEqual(first.status, "counted")
        with self.assertRaises(DuplicateReceipt):
            self.pf.ingest_receipt(r)
        count = self.store.query_one(
            "SELECT COUNT(*) c FROM samples WHERE receipt_id='rdup'"
        )
        self.assertEqual(count["c"], 10)

    def test_late_receipt_after_canary_attributes_to_executed_combo(self) -> None:
        self._release()
        # 平台在 T0+22 收到越界回执并执行回滚（现场发生于同一刻）。
        self.clock.advance(10)
        rollback_at = self.clock.value
        self.pf.ingest_receipt(self._receipt(
            "r-bad", STATIONS[2], "B-new", self._bad_frr_samples(),
            occurred=rollback_at,
            received=rollback_at,
        ))
        self.clock.advance(15)
        # 断网期间（回滚前 2 分钟）执行的限量回执，重连后才送达
        late = self._receipt(
            "r-late", STATIONS[2], "B-new", self._healthy("late", 4),
            occurred=rollback_at - timedelta(minutes=2),
            received=self.clock.value,
        )
        result = self.pf.ingest_receipt(late)
        self.assertEqual(result.status, "counted")
        self.assertEqual(result.stage, "canary")

    def test_post_rollback_impersonation_rejected(self) -> None:
        self._release()
        self.pf.ingest_receipt(self._receipt(
            "r-bad", STATIONS[2], "B-new", self._bad_frr_samples(),
            occurred=self.clock.value + timedelta(minutes=10),
        ))
        self.clock.advance(30)
        forged = self._receipt(
            "r-fake", STATIONS[2], "B-new", self._healthy("f", 4),
            occurred=self.clock.value, received=self.clock.value,
        )
        with self.assertRaises(DomainError):
            self.pf.ingest_receipt(forged)

    def test_unknown_combo_receipt_rejected(self) -> None:
        r = self._receipt(
            "r-ghost", STATIONS[0], "B-never", self._healthy("g", 2),
            occurred=self.clock.value,
        )
        with self.assertRaises(DomainError):
            self.pf.ingest_receipt(r)

    def test_bad_signature_receipt_rejected(self) -> None:
        self._release()
        r = self._receipt(
            "r-sig", STATIONS[0], "B-new", self._healthy("g", 4),
            occurred=self.clock.value + timedelta(minutes=10),
        )
        object.__setattr__(r, "signature", r.signature[:-1] + b"\x00")
        with self.assertRaises(Exception):
            self.pf.ingest_receipt(r)

    def test_active_stage_breach_still_freezes(self) -> None:
        self._release()
        for station in STATIONS:
            self.pf.ingest_receipt(self._receipt(
                f"r-{station}", station, "B-new", self._healthy(station, 24),
                occurred=self.clock.value,
            ))
            self.pf.confirm_station("REL", station, operator="op.zhou")
        self.assertTrue(self.pf.promote("REL").activated)
        self.clock.advance(5)
        # 扩围后误剔除率越界：继续冻结。
        result = self.pf.ingest_receipt(self._receipt(
            "r-active-bad", STATIONS[0], "B-new", self._bad_frr_samples(),
            occurred=self.clock.value,
        ))
        self.assertTrue(result.frozen)
        self.assertTrue(self.store.get_release("REL").frozen)

    def test_promotion_is_atomic_when_midway_write_fails(self) -> None:
        self._release()
        for station in STATIONS:
            self.pf.ingest_receipt(self._receipt(
                f"r-{station}", station, "B-new", self._healthy(station, 24),
                occurred=self.clock.value,
            ))
            self.pf.confirm_station("REL", station, operator="op.zhou")

        original = self.store.open_interval
        calls = {"n": 0}

        def flaky(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 3:  # 第三个工位写阶段区间时崩溃
                raise RuntimeError("simulated crash mid-promotion")
            return original(*args, **kwargs)

        self.store.open_interval = flaky  # type: ignore[assignment]
        with self.assertRaises(RuntimeError):
            self.pf.promote("REL")
        self.store.open_interval = original  # type: ignore[assignment]

        # 重启后：三座工位全部停留在 canary，没有工位半进入 active。
        for station in STATIONS:
            state = self.store.get_station_state(station)
            self.assertEqual(state.stage, Stage.CANARY)
        open_rows = self.store.query(
            """SELECT station_id, COUNT(*) c FROM stage_history
               WHERE ended_at IS NULL GROUP BY station_id"""
        )
        self.assertTrue(all(r["c"] == 1 for r in open_rows))

    # --- 批次封存不可变 --------------------------------------------------

    def test_sealed_batch_stats_immutable_on_late_supplement(self) -> None:
        r1 = self._receipt(
            "r-seal", STATIONS[0], "B-old", self._healthy("a", 10),
            occurred=self.clock.value, batch_id="BAT",
        )
        self.pf.ingest_receipt(r1)
        sealed = self.pf.seal_batch("BAT", actor="quality")
        n_at_seal = sealed["stats"]["overall"]["n"]
        self.assertEqual(n_at_seal, 10)
        # 封存后迟到的同批回执
        late = self._receipt(
            "r-late", STATIONS[0], "B-old", self._healthy("b", 6),
            occurred=self.clock.value + timedelta(minutes=2),
            received=self.clock.value + timedelta(minutes=20),
            batch_id="BAT",
        )
        result = self.pf.ingest_receipt(late)
        self.assertEqual(result.status, "sealed_supplement")
        view = self.pf.sealed_batch("BAT")
        self.assertEqual(view["stats"]["overall"]["n"], 10)
        self.assertEqual(len(view["late_supplements"]), 1)
        # 重复封存幂等，统计不变
        again = self.pf.seal_batch("BAT", actor="quality")
        self.assertTrue(again["already_sealed"])
        self.assertEqual(again["stats"]["overall"]["n"], 10)

    # --- 重启安全 --------------------------------------------------------

    def test_restart_preserves_single_stage(self) -> None:
        db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db.close()
        path = db.name
        store = Store(path)
        try:
            pf, _ = bootstrap(store, self.clock)
            pf.create_release("RELr", "B-new", STATIONS, created_by="eng.zhao")
            pf.approve_release("RELr", approver="quality.li")
            pf.start_shadow("RELr", STATIONS[0], actor="lead")
            self.clock.advance(3)
            for i in range(3):
                pf.record_shadow(
                    "RELr", STATIONS[0], f"s{i}", is_defect=False,
                    incumbent_reject=False, candidate_reject=False, latency_ms=50,
                )
            pf.start_canary("RELr", STATIONS[0], operator="lead")
        finally:
            store.close()

        store2 = Store(path)
        try:
            pf2 = ReleasePlatform(store2, clock=self.clock)
            state = pf2.store.get_station_state(STATIONS[0])
            self.assertEqual(state.stage, Stage.CANARY)
            self.assertEqual(state.bundle_id, "B-new")
            open_rows = store2.query(
                "SELECT COUNT(*) c FROM stage_history WHERE station_id=? AND ended_at IS NULL",
                (STATIONS[0],),
            )
            self.assertEqual(open_rows[0]["c"], 1)  # 任一时刻仅一个生效区间
            grant = pf2.serving_grant(STATIONS[0])
            self.assertEqual(grant.bundle_id, "B-new")
            self.assertTrue(grant.model_signature)
        finally:
            store2.close()
            Path(path).unlink(missing_ok=True)

    def test_no_two_overlapping_intervals_possible(self) -> None:
        self._release()
        intervals = self.store.intervals(STATIONS[0])
        for earlier, later in zip(intervals, intervals[1:]):
            self.assertIsNotNone(earlier.ended_at)
            self.assertLessEqual(earlier.ended_at, later.started_at)


if __name__ == "__main__":
    unittest.main()
