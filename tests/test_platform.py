"""放行平台端到端规则测试。"""

import binascii
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from arm_release.crypto import SigningKey, sha256_digest, sign_payload
from arm_release.models import PlatformError, Thresholds
from arm_release.platform import GateConfig, GateRequirement, Platform
from arm_release.replay import evidence_samples, replay
from arm_release.store import Store

TZ = timezone(timedelta(hours=8))


def at(h: int, m: int = 0, day: int = 10) -> datetime:
    return datetime(2026, 9, day, h, m, tzinfo=TZ)


class Clock:
    def __init__(self, t: datetime):
        self.t = t

    def __call__(self) -> datetime:
        return self.t


def signed_model(key, model_id="m", version="1", blob=b"weights"):
    digest = sha256_digest(blob)
    payload = {"model_id": model_id, "version": version, "digest": digest}
    return {
        "model_id": model_id,
        "version": version,
        "digest": digest,
        "kid": key.kid,
        "signature": sign_payload(key, payload),
        "payload": payload,
    }


def calibration(sid="cal1", at_iso=None):
    body = {
        "snapshot_id": sid,
        "camera_id": "cam1",
        "taken_at": at_iso or at(8).isoformat(),
        "intrinsics": {"fx": 1700.0},
    }
    body["digest"] = sha256_digest(json.dumps(body, sort_keys=True).encode())
    return body


def signed_bundle(rkey, bid, model_doc, cal_doc, recipe="r", rv="1"):
    manifest = {
        "bundle_id": bid,
        "recipe": recipe,
        "recipe_version": rv,
        "model": {
            "model_id": model_doc["model_id"],
            "version": model_doc["version"],
            "digest": model_doc["digest"],
        },
        "calibration": {
            "snapshot_id": cal_doc["snapshot_id"],
            "camera_id": cal_doc["camera_id"],
            "digest": cal_doc["digest"],
        },
    }
    return {
        "bundle_id": bid,
        "kid": rkey.kid,
        "signature": sign_payload(rkey, manifest),
        "parts": {
            "model": {"model_id": model_doc["model_id"], "version": model_doc["version"]},
            "calibration": {"snapshot_id": cal_doc["snapshot_id"]},
            "recipe": recipe,
            "recipe_version": rv,
            "manifest": manifest,
        },
    }


def receipt(rid, station, bid, t, truth="good", decision="accept", latency=50.0,
            received=None, champion=None, batch=None):
    doc = {
        "receipt_id": rid,
        "station_id": station,
        "bundle_id": bid,
        "occurred_at": t.isoformat(),
        "received_at": (received or t).isoformat(),
        "truth": truth,
        "decision": decision,
        "latency_ms": latency,
    }
    if champion is not None:
        doc["champion_decision"] = champion
    if batch is not None:
        doc["batch_id"] = batch
    return doc


def new_platform(path, gates=None):
    store = Store.open(path)
    return Platform(store, gates=gates, clock=Clock(at(9))), store


def bootstrap(path, gates=None):
    """建一个已审批 B0 稳定、B1 已登记审批的平台。"""
    pf, store = new_platform(path, gates)
    mk = SigningKey.generate("mk")
    rk = SigningKey.generate("rk")
    pf.add_trusted_key(mk.public(), "model")
    pf.add_trusted_key(rk.public(), "release")
    pf.register_recipe("r", "1", Thresholds(0.98, 0.02, 120.0))
    m0 = signed_model(mk, "m", "1", b"old")
    c0 = calibration("c0")
    pf.register_model(m0)
    pf.register_calibration(c0)
    b0 = signed_bundle(rk, "B0", m0, c0)
    pf.register_bundle(b0)
    pf.approve_bundle("B0", "qa")
    m1 = signed_model(mk, "m", "2", b"new")
    c1 = calibration("c1", at(8, 30).isoformat())
    pf.register_model(m1)
    pf.register_calibration(c1)
    b1 = signed_bundle(rk, "B1", m1, c1)
    pf.register_bundle(b1)
    pf.approve_bundle("B1", "qa")
    return pf, store, mk, rk


class CryptoVectorTest(unittest.TestCase):
    def test_rfc8032_vector_1(self):
        seed = binascii.unhexlify(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        )
        sk = SigningKey("t", seed)
        self.assertEqual(
            binascii.hexlify(sk.public().raw).decode(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        sig = sk.sign(b"")
        self.assertEqual(
            binascii.hexlify(sig).decode(),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        sk.public().verify(b"", sig)

    def test_roundtrip_and_tamper(self):
        sk = SigningKey.generate("k")
        msg = b"model-bytes" * 10
        sig = sk.sign(msg)
        sk.public().verify(msg, sig)
        with self.assertRaises(Exception):
            sk.public().verify(msg + b"!", sig)


class SignatureEnforcementTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "p.sqlite3"

    def tearDown(self):
        if hasattr(self, "store"):
            self.store.close()
        self.tmp.cleanup()

    def test_tampered_model_rejected(self):
        pf, store, mk, rk = bootstrap(self.path)
        self.store = store
        # 签名载荷与登记摘要被篡改 → 验签失败，拒绝登记
        doc = signed_model(mk, "evil", "1", b"evil")
        doc["payload"]["digest"] = "sha256:deadbeef"
        with self.assertRaises(PlatformError):
            pf.register_model(doc)

    def test_untrusted_key_rejected(self):
        pf, store, mk, rk = bootstrap(self.path)
        self.store = store
        stranger = SigningKey.generate("stranger")
        doc = signed_model(stranger, "x", "1")
        with self.assertRaises(PlatformError):
            pf.register_model(doc)

    def test_bundle_missing_calibration_rejected(self):
        pf, store, mk, rk = bootstrap(self.path)
        self.store = store
        m = signed_model(mk, "m", "9", b"z")
        pf.register_model(m)
        c = calibration("ghost")
        doc = signed_bundle(rk, "BG", m, c)
        with self.assertRaises(PlatformError):
            pf.register_bundle(doc)

    def test_bundle_signature_must_cover_all_three_parts(self):
        pf, store, mk, rk = bootstrap(self.path)
        self.store = store
        # 篡改 manifest 中配方版本后签名失效
        m = signed_model(mk, "m", "7", b"z")
        c = calibration("c7")
        pf.register_model(m)
        pf.register_calibration(c)
        pf.register_recipe("r", "2", Thresholds(0.9, 0.05, 200.0))
        doc = signed_bundle(rk, "B7", m, c, "r", "2")
        doc["parts"]["recipe_version"] = "1"
        with self.assertRaises(PlatformError):
            pf.register_bundle(doc)


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "p.sqlite3"
        gates = GateConfig(
            shadow=GateRequirement(4, 4),
            canary=GateRequirement(4),
            rollout=GateRequirement(4),
        )
        self.pf, self.store, _, _ = bootstrap(self.path, gates)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _shadow_pairs(self, station, n=4, start=9):
        for i in range(n):
            res = self.pf.report_receipt(
                receipt(f"s-{station}-{i}", station, "B1", at(start, i),
                        truth="defect" if i == 1 else "good",
                        decision="reject" if i == 1 else "accept",
                        champion="reject" if i == 1 else "accept")
            )
            self.assertEqual(res.outcome, "counted")

    def test_approval_executor_separation(self):
        with self.assertRaises(PlatformError):
            self.pf.start_shadow("st1", "B1", "qa")  # 审批人自己执行
        self.pf.start_shadow("st1", "B1", "ops")

    def test_unapproved_bundle_cannot_serve(self):
        mk = SigningKey.generate("mk2")
        rk = SigningKey.generate("rk2")
        self.pf.add_trusted_key(mk.public(), "model")
        self.pf.add_trusted_key(rk.public(), "release")
        self.pf.register_recipe("r", "3", Thresholds(0.9, 0.1, 999))
        m = signed_model(mk, "m", "3", b"z3")
        c = calibration("c3")
        self.pf.register_model(m)
        self.pf.register_calibration(c)
        self.pf.register_bundle(signed_bundle(rk, "B9", m, c, "r", "3"))
        with self.assertRaises(PlatformError):
            self.pf.start_shadow("stX", "B9", "ops")

    def test_gate_blocks_without_samples_then_promotes(self):
        self.pf.establish_stable("st1", "B0", at(8).isoformat())
        self.pf.start_shadow("st1", "B1", "ops")
        # 影子期机械臂仍吃稳定组合
        self.assertEqual(self.pf.serving_view("st1")["arm_serves"]["bundle_id"], "B0")
        with self.assertRaises(PlatformError):
            self.pf.promote("st1", "B1", "ops")
        self._shadow_pairs("st1")
        self.assertEqual(self.pf.promote("st1", "B1", "ops"), "canary")
        # canary 开始驱动机械臂
        self.assertEqual(self.pf.serving_view("st1")["arm_serves"]["bundle_id"], "B1")

    def test_late_duplicate_and_stray(self):
        self.pf.establish_stable("st1", "B0", at(8).isoformat())
        self.pf.start_shadow("st1", "B1", "ops")
        self._shadow_pairs("st1")
        self.pf.promote("st1", "B1", "ops")
        # canary 4 个样本（含 1 个缺陷并抓出，召回率可评估）
        for i in range(4):
            self.pf.report_receipt(
                receipt(f"c-{i}", "st1", "B1", at(9, 20 + i),
                        truth="defect" if i == 0 else "good",
                        decision="reject" if i == 0 else "accept",
                        latency=40 + i)
            )
        self.pf.promote("st1", "B1", "ops")
        # 扩围窗口产生一条回执但断网，13:00 才送达
        late = receipt("late1", "st1", "B1", at(10, 5), received=at(13))
        r = self.pf.report_receipt(late)
        self.assertEqual(r.outcome, "counted")
        self.assertEqual(r.counted_phase, "rollout")
        # 重传：只计一次
        self.assertEqual(self.pf.report_receipt(dict(late)).outcome, "duplicate")
        # 回滚后送达的 B1 回执（发生时间也在回滚之后）→ 隔离
        self.pf.freeze("B1", {"manual": True}, "qa")
        stray = receipt("stray1", "st1", "B1", at(12, 30), received=at(13, 5))
        self.assertEqual(
            self.pf.report_receipt(stray).quarantine_reason,
            "no_execution_interval_at_occurred_at",
        )

    def test_breach_freezes_and_unconfirmed_stations_revert(self):
        # st1 已确认 B1 全量；st2 仍在扩围
        for station in ("st1", "st2"):
            self.pf.establish_stable(station, "B0", at(8).isoformat())
            self.pf.start_shadow(station, "B1", "ops")
            self._shadow_pairs(station)
            self.pf.promote(station, "B1", "ops")
            for i in range(4):
                self.pf.report_receipt(
                    receipt(f"ca-{station}-{i}", station, "B1", at(9, 20 + i),
                            truth="defect" if i == 0 else "good",
                            decision="reject" if i == 0 else "accept",
                            latency=50)
                )
            self.pf.promote(station, "B1", "ops")
            if station == "st1":
                for i in range(4):
                    self.pf.report_receipt(
                        receipt(f"ro-{station}-{i}", station, "B1", at(10, i),
                                truth="defect" if i == 0 else "good",
                                decision="reject" if i == 0 else "accept",
                                latency=50)
                    )
                self.pf.promote("st1", "B1", "ops")  # active
                self.assertEqual(self.pf.station_status("st1")["stable_bundle"], "B1")
        # st2 第 4 条扩围样本为良品误剔除 → FRR 越界（3 良品 1 误剔）
        for i in range(3):
            self.pf.report_receipt(
                receipt(f"ro2-{i}", "st2", "B1", at(10, 10 + i), latency=50)
            )
        res = self.pf.report_receipt(
            receipt("trig", "st2", "B1", at(10, 14), truth="good", decision="reject",
                    latency=50)
        )
        self.assertTrue(res.triggered_freeze)
        # 未确认的 st2 回 B0；已确认的 st1 保持 B1
        self.assertIsNone(self.pf.station_status("st2")["pipeline"])
        self.assertEqual(self.pf.station_status("st2")["stable_bundle"], "B0")
        self.assertEqual(self.pf.serving_view("st2")["arm_serves"]["bundle_id"], "B0")
        self.assertEqual(self.pf.serving_view("st1")["arm_serves"]["bundle_id"], "B1")
        # 冻结后禁止扩围
        with self.assertRaises(PlatformError):
            self.pf.start_shadow("st3", "B1", "ops")

    def test_sealed_batch_stats_immutable(self):
        self.pf.establish_stable("st1", "B0", at(8).isoformat())
        self.pf.report_receipt(receipt("b1", "st1", "B0", at(8, 5), batch="LOT"))
        summary = self.pf.seal_batch("LOT")
        before = json.dumps(summary, sort_keys=True)
        # 封存后补数
        r = self.pf.report_receipt(
            receipt("b2", "st1", "B0", at(8, 6), received=at(15), batch="LOT")
        )
        self.assertEqual(r.quarantine_reason, "batch_sealed_late_backfill")
        # 已封存不可再封
        with self.assertRaises(PlatformError):
            self.pf.seal_batch("LOT")
        after = json.dumps(self.pf.sealed_batch_summary("LOT"), sort_keys=True)
        self.assertEqual(before, after)

    def test_restart_keeps_single_phase_and_signed_serving(self):
        self.pf.establish_stable("st1", "B0", at(8).isoformat())
        self.pf.start_shadow("st1", "B1", "ops")
        self._shadow_pairs("st1")
        self.pf.promote("st1", "B1", "ops")
        self.store.close()
        store = Store.open(self.path)
        pf2 = Platform(
            store,
            gates=GateConfig(
                shadow=GateRequirement(4, 4), canary=GateRequirement(4),
                rollout=GateRequirement(4),
            ),
            clock=Clock(at(10)),
        )
        status = pf2.station_status("st1")
        self.assertEqual(status["stable_bundle"], "B0")
        self.assertEqual(status["pipeline"]["phase"], "canary")
        view = pf2.serving_view("st1")
        self.assertEqual(view["arm_serves"]["bundle_id"], "B1")
        self.assertIn("model_signature", view["arm_serves"])
        store.close()


class ReplayTest(unittest.TestCase):
    def test_demo_report_is_actionable(self):
        from arm_release.demo_incident import build_demo

        with tempfile.TemporaryDirectory() as d:
            report = build_demo(Path(d) / "inc.sqlite3")
        self.assertEqual(report["affected_products"][0]["recipe"], "housing-a17")
        # 三座工位都有完整 shadow→canary→rollout→回滚 区间
        stations = {iv["station_id"] for iv in report["intervals"]}
        self.assertEqual(stations, {"arm-cell-01", "arm-cell-02", "arm-cell-03"})
        phases = {(iv["station_id"], iv["phase"]) for iv in report["intervals"]}
        for s in stations:
            for ph in ("shadow", "canary", "rollout", "stable"):
                self.assertIn((s, ph), phases)
        # 三座工位均在 12:05 回滚
        self.assertEqual({rb["station_id"] for rb in report["rollbacks"]}, stations)
        for rb in report["rollbacks"]:
            self.assertEqual(rb["at"], "2026-09-10T12:05:00+08:00")
            self.assertEqual(rb["reverted_to"], "B0")
        # 触发证据唯一且指向 arm-cell-03 的误剔除样本
        self.assertEqual(len(report["evidence_samples"]), 1)
        ev = report["evidence_samples"][0]
        self.assertEqual(ev["station_id"], "arm-cell-03")
        self.assertEqual(ev["truth"], "good")
        self.assertEqual(ev["decision"], "reject")
        self.assertEqual(ev["breached"], ["false_reject_rate"])
        self.assertEqual(
            set(ev["rollback_propagated_to"]),
            {"arm-cell-01", "arm-cell-02", "arm-cell-03"},
        )
        self.assertTrue(report["sealed_summary_unchanged"])
        self.assertTrue(report["restart_invariant_held"])
        self.assertEqual(set(report["serving_after_rollback"].values()), {"B0"})


if __name__ == "__main__":
    unittest.main()
