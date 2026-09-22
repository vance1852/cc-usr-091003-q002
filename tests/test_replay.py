"""换线事故场景的重放与取证测试。"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from arm_release.contracts import EventEnvelope, load_events
from arm_release.projector import EventProjector
from arm_release.replay import Forensics
from arm_release.scenario import build_incident
from arm_release.service import ReleasePlatform
from arm_release.store import Store


class IncidentReplayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scenario = build_incident()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db_path = str(Path(cls.tmp.name) / "incident.db")
        store = Store(cls.db_path)
        cls.platform = ReleasePlatform(store)
        cls.projector = EventProjector(cls.platform)
        events = [EventEnvelope.from_dict(e) for e in cls.scenario["events"]]
        cls.stats = cls.projector.replay(events)
        cls.store = store
        cls.report = Forensics(store).report()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.store.close()
        cls.tmp.cleanup()

    def test_one_dead_letter_for_post_rollback_receipt(self) -> None:
        self.assertEqual(self.stats.dead_lettered, 1)
        dead = self.store.query("SELECT event_id FROM projection_dead_letter")
        self.assertEqual([r["event_id"] for r in dead], ["a17-901"])

    def test_affected_product_is_housing_a17(self) -> None:
        products = self.report["affected_products"]
        self.assertEqual([p["recipe_id"] for p in products], ["housing-a17"])
        self.assertEqual(
            set(products[0]["stations"]),
            {"arm-cell-01", "arm-cell-02", "arm-cell-03"},
        )

    def test_cell03_rolled_back_to_stable(self) -> None:
        intervals = self.report["station_intervals"]["arm-cell-03"]
        stages = [(i["bundle_id"], i["stage"]) for i in intervals]
        self.assertIn(("B-candidate-v8", "canary"), stages)
        self.assertIn(("B-candidate-v8", "rolled_back"), stages)
        self.assertEqual(stages[-1], ("B-stable-v7", "active"))
        self.assertTrue(intervals[-1]["confirmed"])

    def test_cells_01_02_remain_confirmed_canary_but_frozen(self) -> None:
        for station in ("arm-cell-01", "arm-cell-02"):
            last = self.report["station_intervals"][station][-1]
            self.assertEqual(last["stage"], "canary")
            self.assertTrue(last["confirmed"])
        release = self.store.get_release("R-v8-rollout")
        self.assertTrue(release.frozen)

    def test_rollback_trigger_evidence(self) -> None:
        triggers = self.report["rollback_triggers"]
        self.assertEqual(len(triggers), 1)
        trigger = triggers[0]
        self.assertEqual(trigger["station_id"], "arm-cell-03")
        self.assertEqual(trigger["receipt_id"], "rcp-03-canary-1")
        self.assertTrue(any("误剔除" in r for r in trigger["reasons"]))
        flagged = [s for s in trigger["samples"] if s["false_rejected"]]
        self.assertEqual(len(flagged), 4)

    def test_duplicate_receipt_counted_once(self) -> None:
        row = self.store.query_one(
            "SELECT COUNT(*) c FROM samples WHERE receipt_id='rcp-03-canary-1'"
        )
        self.assertEqual(row["c"], 24)

    def test_sealed_batches_immutable_with_supplements(self) -> None:
        sealed = {b["batch_id"]: b for b in self.report["sealed_batches"]}
        self.assertEqual(sealed["B20260910-A"]["stats"]["overall"]["n"], 90)
        batch_b = sealed["B20260910-B"]
        self.assertEqual(batch_b["stats"]["overall"]["n"], 60)
        self.assertEqual(batch_b["late_supplement_count"], 1)
        self.assertEqual(
            batch_b["late_supplement_receipts"], ["rcp-02-morning-B-late"]
        )

    def test_serving_grants_after_replay(self) -> None:
        self.assertEqual(
            self.platform.serving_grant("arm-cell-01").bundle_id, "B-candidate-v8"
        )
        self.assertEqual(
            self.platform.serving_grant("arm-cell-03").bundle_id, "B-stable-v7"
        )
        for station in ("arm-cell-01", "arm-cell-02", "arm-cell-03"):
            self.assertTrue(self.platform.serving_grant(station).model_signature)

    def test_replay_is_idempotent(self) -> None:
        events = [EventEnvelope.from_dict(e) for e in self.scenario["events"]]
        again = self.projector.replay(events)
        # 57 个已应用事件跳过；死信事件重试后仍被隔离（修复数据后即可重处理）。
        self.assertEqual(again.applied, 0)
        self.assertEqual(again.skipped, len(events) - 1)
        self.assertEqual(again.dead_lettered, 1)
        self.assertEqual(Forensics(self.store).report(), self.report)

    def test_no_overlapping_open_intervals(self) -> None:
        for station in ("arm-cell-01", "arm-cell-02", "arm-cell-03"):
            rows = self.store.query(
                "SELECT COUNT(*) c FROM stage_history WHERE station_id=? AND ended_at IS NULL",
                (station,),
            )
            self.assertEqual(rows[0]["c"], 1)

    def test_fixture_file_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scenario.json"
            path.write_text(
                json.dumps(self.scenario, ensure_ascii=False), encoding="utf-8"
            )
            scenario, events = load_events(path)
            self.assertEqual(scenario, "line-change-a17-full")
            self.assertEqual(len(events), len(self.scenario["events"]))


class ProjectorGuardTest(unittest.TestCase):
    def test_unknown_event_dead_lettered(self) -> None:
        store = Store(":memory:")
        try:
            pf = ReleasePlatform(store)
            projector = EventProjector(pf)
            event = EventEnvelope(
                event_id="x1", kind="mystery_event",
                occurred_at="2026-09-10T08:00:00+08:00",
                received_at="2026-09-10T08:01:00+08:00",
                attributes={},
            )
            stats = projector.replay([event])
            self.assertEqual(stats.dead_lettered, 1)
            self.assertEqual(stats.applied, 0)
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
