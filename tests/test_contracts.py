"""核对仓库随附的领域事件样例。"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from arm_release.contracts import load_events


class FixtureContractTest(unittest.TestCase):
    def test_incident_fixture_is_valid(self) -> None:
        scenario, events = load_events(ROOT / "fixtures" / "incident.json")
        self.assertEqual("line-change-a17", scenario)
        self.assertEqual(4, len(events))
        self.assertEqual(len(events), len({event.event_id for event in events}))

    def test_fixture_keeps_domain_attributes(self) -> None:
        raw = json.loads((ROOT / "fixtures" / "incident.json").read_text(encoding="utf-8"))
        self.assertTrue(all(event["attributes"] for event in raw["events"]))


if __name__ == "__main__":
    unittest.main()