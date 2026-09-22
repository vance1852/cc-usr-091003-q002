"""SQLite 持久化。所有状态迁移与写入在单个事务内完成，
保证服务重启后一座工位至多属于一个候选发布阶段，且在役组合只可能来自
已签名的发布组合。
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trusted_keys (
    kid TEXT PRIMARY KEY,
    role TEXT NOT NULL CHECK (role IN ('model', 'release')),
    x TEXT NOT NULL,
    added_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS models (
    model_id TEXT NOT NULL,
    version TEXT NOT NULL,
    digest TEXT NOT NULL,
    kid TEXT NOT NULL,
    signature TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    PRIMARY KEY (model_id, version)
);

CREATE TABLE IF NOT EXISTS calibrations (
    snapshot_id TEXT PRIMARY KEY,
    camera_id TEXT NOT NULL,
    digest TEXT NOT NULL,
    taken_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    registered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recipes (
    recipe TEXT NOT NULL,
    version TEXT NOT NULL,
    thresholds_json TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    PRIMARY KEY (recipe, version)
);

CREATE TABLE IF NOT EXISTS bundles (
    bundle_id TEXT PRIMARY KEY,
    model_id TEXT NOT NULL,
    model_version TEXT NOT NULL,
    calibration_id TEXT NOT NULL,
    recipe TEXT NOT NULL,
    recipe_version TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    kid TEXT NOT NULL,
    signature TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    approved_by TEXT,
    approved_at TEXT
);

-- 一座工位至多一条未终结的候选流水线（shadow/canary/rollout）。
CREATE TABLE IF NOT EXISTS station_pipeline (
    station_id TEXT PRIMARY KEY,
    bundle_id TEXT NOT NULL,
    phase TEXT NOT NULL,
    since TEXT NOT NULL,
    prev_bundle_id TEXT,
    executor TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS station_stable (
    station_id TEXT PRIMARY KEY,
    bundle_id TEXT NOT NULL,
    since TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rollout_state (
    bundle_id TEXT PRIMARY KEY,
    frozen INTEGER NOT NULL DEFAULT 0,
    frozen_at TEXT,
    reason_json TEXT
);

CREATE TABLE IF NOT EXISTS stage_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    station_id TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    action TEXT NOT NULL,
    phase TEXT,
    at_time TEXT NOT NULL,
    actor TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_stage_events_station_bundle
    ON stage_events(station_id, bundle_id, at_time);

CREATE TABLE IF NOT EXISTS receipts (
    receipt_id TEXT PRIMARY KEY,
    station_id TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    batch_id TEXT,
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    truth TEXT NOT NULL,
    decision TEXT NOT NULL,
    latency_ms REAL NOT NULL,
    champion_decision TEXT,
    counted_phase TEXT NOT NULL,
    quarantined INTEGER NOT NULL DEFAULT 0,
    raw_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_receipts_window
    ON receipts(station_id, bundle_id, counted_phase, quarantined);
CREATE INDEX IF NOT EXISTS idx_receipts_batch ON receipts(batch_id);

CREATE TABLE IF NOT EXISTS sealed_batches (
    batch_id TEXT PRIMARY KEY,
    sealed_at TEXT NOT NULL,
    summary_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sealed_batch_stats (
    batch_id TEXT NOT NULL,
    station_id TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    metrics_json TEXT NOT NULL,
    PRIMARY KEY (batch_id, station_id, bundle_id)
);
"""


class Store:
    """薄 SQL 封装，不做业务判定。"""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    @classmethod
    def open(cls, path: str | Path) -> "Store":
        path = Path(path)
        if path.parent != Path("."):
            path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), isolation_level=None, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.row_factory = sqlite3.Row
        store = cls(conn)
        store.create_schema()
        return store

    def create_schema(self) -> None:
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    # -- 事务 -------------------------------------------------------------

    @contextmanager
    def transaction(self):
        """显式事务：BEGIN IMMEDIATE 立即取写锁，提交或整体回滚。"""

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    # -- meta -------------------------------------------------------------

    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    # -- 基础清单 -----------------------------------------------------------

    def add_key(self, kid: str, role: str, x: str, added_at: str) -> None:
        self.conn.execute(
            "INSERT INTO trusted_keys(kid, role, x, added_at) VALUES(?,?,?,?)",
            (kid, role, x, added_at),
        )

    def get_key(self, kid: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM trusted_keys WHERE kid=?", (kid,)
        ).fetchone()

    def add_model(self, m: Any, registered_at: str) -> None:
        self.conn.execute(
            "INSERT INTO models(model_id, version, digest, kid, signature, "
            "payload_json, registered_at) VALUES(?,?,?,?,?,?,?)",
            (
                m.model_id,
                m.version,
                m.digest,
                m.kid,
                m.signature,
                json.dumps(m.payload, ensure_ascii=False),
                registered_at,
            ),
        )

    def get_model(self, model_id: str, version: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM models WHERE model_id=? AND version=?", (model_id, version)
        ).fetchone()

    def add_calibration(self, c: Any, registered_at: str) -> None:
        self.conn.execute(
            "INSERT INTO calibrations(snapshot_id, camera_id, digest, taken_at, "
            "payload_json, registered_at) VALUES(?,?,?,?,?,?)",
            (
                c.snapshot_id,
                c.camera_id,
                c.digest,
                c.taken_at,
                json.dumps(
                    {
                        "snapshot_id": c.snapshot_id,
                        "camera_id": c.camera_id,
                        "taken_at": c.taken_at,
                        "intrinsics": c.intrinsics,
                    },
                    ensure_ascii=False,
                ),
                registered_at,
            ),
        )

    def get_calibration(self, snapshot_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM calibrations WHERE snapshot_id=?", (snapshot_id,)
        ).fetchone()

    def add_recipe(
        self, recipe: str, version: str, thresholds_json: str, registered_at: str
    ) -> None:
        self.conn.execute(
            "INSERT INTO recipes(recipe, version, thresholds_json, registered_at) "
            "VALUES(?,?,?,?)",
            (recipe, version, thresholds_json, registered_at),
        )

    def get_recipe(self, recipe: str, version: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM recipes WHERE recipe=? AND version=?", (recipe, version)
        ).fetchone()

    # -- 发布组合 -----------------------------------------------------------

    def add_bundle(self, b: Any, signature: str, kid: str, registered_at: str) -> None:
        self.conn.execute(
            "INSERT INTO bundles(bundle_id, model_id, model_version, calibration_id, "
            "recipe, recipe_version, manifest_json, kid, signature, registered_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                b.bundle_id,
                b.model.model_id,
                b.model.version,
                b.calibration.snapshot_id,
                b.recipe,
                b.recipe_version,
                json.dumps(b.manifest(), ensure_ascii=False),
                kid,
                signature,
                registered_at,
            ),
        )

    def get_bundle(self, bundle_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM bundles WHERE bundle_id=?", (bundle_id,)
        ).fetchone()

    def approve_bundle(self, bundle_id: str, approver: str, at: str) -> None:
        self.conn.execute(
            "UPDATE bundles SET approved_by=?, approved_at=? WHERE bundle_id=?",
            (approver, at, bundle_id),
        )

    def list_pipelines(self, bundle_id: str | None = None) -> list[sqlite3.Row]:
        if bundle_id is None:
            return list(self.conn.execute("SELECT * FROM station_pipeline"))
        return list(
            self.conn.execute(
                "SELECT * FROM station_pipeline WHERE bundle_id=?", (bundle_id,)
            )
        )

    def get_pipeline(self, station_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM station_pipeline WHERE station_id=?", (station_id,)
        ).fetchone()

    def upsert_pipeline(
        self,
        station_id: str,
        bundle_id: str,
        phase: str,
        since: str,
        prev_bundle_id: str | None,
        executor: str,
    ) -> None:
        self.conn.execute(
            "INSERT INTO station_pipeline(station_id, bundle_id, phase, since, "
            "prev_bundle_id, executor) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(station_id) DO UPDATE SET "
            "bundle_id=excluded.bundle_id, phase=excluded.phase, since=excluded.since, "
            "prev_bundle_id=excluded.prev_bundle_id, executor=excluded.executor",
            (station_id, bundle_id, phase, since, prev_bundle_id, executor),
        )

    def delete_pipeline(self, station_id: str) -> None:
        self.conn.execute("DELETE FROM station_pipeline WHERE station_id=?", (station_id,))

    def get_stable(self, station_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM station_stable WHERE station_id=?", (station_id,)
        ).fetchone()

    def upsert_stable(self, station_id: str, bundle_id: str, since: str) -> None:
        self.conn.execute(
            "INSERT INTO station_stable(station_id, bundle_id, since) VALUES(?,?,?) "
            "ON CONFLICT(station_id) DO UPDATE SET bundle_id=excluded.bundle_id, "
            "since=excluded.since",
            (station_id, bundle_id, since),
        )

    def get_rollout(self, bundle_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM rollout_state WHERE bundle_id=?", (bundle_id,)
        ).fetchone()

    def init_rollout(self, bundle_id: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO rollout_state(bundle_id, frozen) VALUES(?,0)",
            (bundle_id,),
        )

    def freeze_rollout(self, bundle_id: str, at: str, reason: dict[str, Any]) -> None:
        self.conn.execute(
            "UPDATE rollout_state SET frozen=1, frozen_at=?, reason_json=? "
            "WHERE bundle_id=?",
            (at, json.dumps(reason, ensure_ascii=False), bundle_id),
        )

    # -- 时间线事件 ----------------------------------------------------------

    def add_stage_event(
        self,
        station_id: str,
        bundle_id: str,
        action: str,
        at: str,
        phase: str | None = None,
        actor: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO stage_events(station_id, bundle_id, action, phase, at_time, "
            "actor, detail_json) VALUES(?,?,?,?,?,?,?)",
            (
                station_id,
                bundle_id,
                action,
                phase,
                at,
                actor,
                json.dumps(detail or {}, ensure_ascii=False),
            ),
        )
        return int(cur.lastrowid)

    def list_stage_events(
        self, station_id: str | None = None, bundle_id: str | None = None
    ) -> list[sqlite3.Row]:
        clauses: list[str] = []
        params: list[Any] = []
        if station_id:
            clauses.append("station_id=?")
            params.append(station_id)
        if bundle_id:
            clauses.append("bundle_id=?")
            params.append(bundle_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        return list(
            self.conn.execute(
                f"SELECT * FROM stage_events{where} ORDER BY at_time, id", params
            )
        )

    # -- 回执 ---------------------------------------------------------------

    def get_receipt(self, receipt_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM receipts WHERE receipt_id=?", (receipt_id,)
        ).fetchone()

    def insert_receipt(self, r: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO receipts(receipt_id, station_id, bundle_id, batch_id, "
            "occurred_at, received_at, truth, decision, latency_ms, "
            "champion_decision, counted_phase, quarantined, raw_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                r["receipt_id"],
                r["station_id"],
                r["bundle_id"],
                r.get("batch_id"),
                r["occurred_at"],
                r["received_at"],
                r["truth"],
                r["decision"],
                float(r["latency_ms"]),
                r.get("champion_decision"),
                r["counted_phase"],
                1 if r.get("quarantined") else 0,
                json.dumps(r.get("raw", {}), ensure_ascii=False),
            ),
        )

    def count_receipts(
        self,
        station_id: str,
        bundle_id: str,
        phase: str,
        batch_id: str | None = None,
    ) -> list[sqlite3.Row]:
        sql = (
            "SELECT * FROM receipts WHERE station_id=? AND bundle_id=? "
            "AND counted_phase=? AND quarantined=0"
        )
        params: list[Any] = [station_id, bundle_id, phase]
        if batch_id is not None:
            sql += " AND batch_id=?"
            params.append(batch_id)
        return list(self.conn.execute(sql, params))

    def list_batch_receipts(self, batch_id: str) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT * FROM receipts WHERE batch_id=? AND quarantined=0",
                (batch_id,),
            )
        )

    def list_quarantined(self, batch_id: str | None = None) -> list[sqlite3.Row]:
        if batch_id is None:
            return list(self.conn.execute("SELECT * FROM receipts WHERE quarantined=1"))
        return list(
            self.conn.execute(
                "SELECT * FROM receipts WHERE quarantined=1 AND batch_id=?", (batch_id,)
            )
        )

    # -- 封存批次 ------------------------------------------------------------

    def seal_batch(self, batch_id: str, at: str, summary: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO sealed_batches(batch_id, sealed_at, summary_json) "
            "VALUES(?,?,?)",
            (batch_id, at, json.dumps(summary, ensure_ascii=False)),
        )

    def get_sealed_batch(self, batch_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM sealed_batches WHERE batch_id=?", (batch_id,)
        ).fetchone()

    def add_sealed_stat(
        self, batch_id: str, station_id: str, bundle_id: str, metrics: dict[str, Any]
    ) -> None:
        self.conn.execute(
            "INSERT INTO sealed_batch_stats(batch_id, station_id, bundle_id, "
            "metrics_json) VALUES(?,?,?,?)",
            (batch_id, station_id, bundle_id, json.dumps(metrics, ensure_ascii=False)),
        )

    def list_sealed_stats(self, batch_id: str) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT * FROM sealed_batch_stats WHERE batch_id=?", (batch_id,)
            )
        )
