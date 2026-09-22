"""SQLite 持久化。

设计要点：
- 所有写操作在单个 IMMEDIATE 事务中完成，进程崩溃后只会出现
  「整笔提交」或「整笔不存在」，不会留下跨半个阶段的工位状态。
- stage_history 记录工位阶段的半开区间 [started_at, ended_at)，
  任何新阶段都在同一事务内关闭上一区间，重叠在写入处即被拒绝。
- receipts 以 receipt_id 为主键，重复回执天然只计一次。
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator

from .domain import (
    Bundle,
    CalibrationRecord,
    ModelRecord,
    RecipeRecord,
    Release,
    Stage,
    StageInterval,
    StationState,
    Thresholds,
    parse_ts,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS signing_keys (
    key_id TEXT PRIMARY KEY,
    jwk_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS models (
    model_id TEXT PRIMARY KEY,
    digest TEXT NOT NULL,
    signature TEXT NOT NULL,
    key_id TEXT NOT NULL REFERENCES signing_keys(key_id),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS calibrations (
    calib_id TEXT PRIMARY KEY,
    station_id TEXT NOT NULL,
    digest TEXT NOT NULL,
    signature TEXT,
    key_id TEXT REFERENCES signing_keys(key_id),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS recipes (
    recipe_id TEXT PRIMARY KEY,
    digest TEXT NOT NULL,
    thresholds_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bundles (
    bundle_id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    model_id TEXT NOT NULL REFERENCES models(model_id),
    recipe_id TEXT NOT NULL REFERENCES recipes(recipe_id),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bundle_calibs (
    bundle_id TEXT NOT NULL REFERENCES bundles(bundle_id),
    station_id TEXT NOT NULL,
    calib_id TEXT NOT NULL REFERENCES calibrations(calib_id),
    PRIMARY KEY (bundle_id, station_id)
);
CREATE TABLE IF NOT EXISTS releases (
    release_id TEXT PRIMARY KEY,
    bundle_id TEXT NOT NULL REFERENCES bundles(bundle_id),
    stations_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    approved_by TEXT,
    approved_at TEXT,
    frozen INTEGER NOT NULL DEFAULT 0,
    freeze_reason TEXT
);
CREATE TABLE IF NOT EXISTS stage_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    station_id TEXT NOT NULL,
    release_id TEXT,
    bundle_id TEXT,
    stage TEXT NOT NULL,
    confirmed INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL,
    ended_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_history_station_start
    ON stage_history(station_id, started_at);
CREATE TABLE IF NOT EXISTS station_state (
    station_id TEXT PRIMARY KEY,
    release_id TEXT,
    bundle_id TEXT,
    stage TEXT NOT NULL,
    confirmed INTEGER NOT NULL DEFAULT 0,
    since TEXT NOT NULL,
    history_id INTEGER NOT NULL REFERENCES stage_history(id)
);
CREATE TABLE IF NOT EXISTS shadow_observations (
    release_id TEXT NOT NULL,
    station_id TEXT NOT NULL,
    sample_id TEXT NOT NULL,
    is_defect INTEGER NOT NULL,
    incumbent_reject INTEGER NOT NULL,
    candidate_reject INTEGER NOT NULL,
    latency_ms REAL NOT NULL,
    PRIMARY KEY (release_id, station_id, sample_id)
);
CREATE TABLE IF NOT EXISTS receipts (
    receipt_id TEXT PRIMARY KEY,
    station_id TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    batch_id TEXT,
    key_id TEXT,
    signature TEXT,
    sealed_batch INTEGER NOT NULL DEFAULT 0,
    is_late INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_receipts_combo
    ON receipts(station_id, bundle_id);
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_id TEXT NOT NULL REFERENCES receipts(receipt_id),
    station_id TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    batch_id TEXT,
    stage TEXT NOT NULL,
    sample_id TEXT NOT NULL,
    is_defect INTEGER NOT NULL,
    model_reject INTEGER NOT NULL,
    latency_ms REAL NOT NULL,
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    UNIQUE (receipt_id, sample_id)
);
CREATE INDEX IF NOT EXISTS idx_samples_combo ON samples(station_id, bundle_id);
CREATE TABLE IF NOT EXISTS batch_seals (
    batch_id TEXT PRIMARY KEY,
    sealed_at TEXT NOT NULL,
    stats_json TEXT NOT NULL,
    receipt_ids_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS batch_supplements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batch_seals(batch_id),
    receipt_id TEXT NOT NULL UNIQUE,
    station_id TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    sample_count INTEGER NOT NULL,
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rollback_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    release_id TEXT NOT NULL,
    station_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    metrics_json TEXT NOT NULL,
    triggered_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail_json TEXT NOT NULL
);
"""


class Store:
    """线程安全的 SQLite 包装；写串行化，读自动提交快照。"""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._path = str(path)
        if self._path != ":memory:":
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self._path, check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(SCHEMA)
        self._depth = 0

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    # --- 事务原语：支持嵌套（内层为 SAVEPOINT） ---------------------------

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            if self._depth == 0:
                self._conn.execute("BEGIN IMMEDIATE")
                self._depth = 1
                savepoint: str | None = None
            else:
                savepoint = f"sp_{self._depth}"
                self._conn.execute(f"SAVEPOINT {savepoint}")
                self._depth += 1
            try:
                yield
            except BaseException:
                if savepoint is None:
                    self._conn.execute("ROLLBACK")
                    self._depth = 0
                else:
                    self._conn.execute(f"ROLLBACK TO {savepoint}")
                    self._conn.execute(f"RELEASE {savepoint}")
                    self._depth -= 1
                raise
            else:
                if savepoint is None:
                    self._conn.execute("COMMIT")
                    self._depth = 0
                else:
                    self._conn.execute(f"RELEASE {savepoint}")
                    self._depth -= 1

    def begin(self) -> None:
        # 兼容旧调用；新代码请用 transaction()。
        if self._depth == 0:
            self._conn.execute("BEGIN IMMEDIATE")
            self._depth = 1

    def commit(self) -> None:
        if self._depth == 1:
            self._conn.execute("COMMIT")
            self._depth = 0

    def rollback(self) -> None:
        if self._depth >= 1:
            self._conn.execute("ROLLBACK")
            self._depth = 0

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, tuple(params)))

    def query_one(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchone()

    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        return self._conn.execute(sql, tuple(params))

    # --- 审计 ------------------------------------------------------------

    def audit(self, actor: str, action: str, detail: dict[str, Any], ts: str) -> None:
        self.execute(
            "INSERT INTO audit_log(ts, actor, action, detail_json) VALUES (?,?,?,?)",
            (ts, actor, action, json.dumps(detail, ensure_ascii=False, sort_keys=True)),
        )

    # --- 资产读取 --------------------------------------------------------

    def get_model(self, model_id: str) -> ModelRecord | None:
        row = self.query_one(
            "SELECT * FROM models WHERE model_id=?", (model_id,)
        )
        if row is None:
            return None
        from .domain import b64d

        return ModelRecord(
            model_id=row["model_id"],
            digest=row["digest"],
            signature=b64d(row["signature"]),
            key_id=row["key_id"],
        )

    def get_calibration(self, calib_id: str) -> CalibrationRecord | None:
        row = self.query_one("SELECT * FROM calibrations WHERE calib_id=?", (calib_id,))
        if row is None:
            return None
        from .domain import b64d

        return CalibrationRecord(
            calib_id=row["calib_id"],
            station_id=row["station_id"],
            digest=row["digest"],
            signature=b64d(row["signature"]) if row["signature"] else None,
            key_id=row["key_id"],
        )

    def get_recipe(self, recipe_id: str) -> RecipeRecord | None:
        row = self.query_one("SELECT * FROM recipes WHERE recipe_id=?", (recipe_id,))
        if row is None:
            return None
        raw = json.loads(row["thresholds_json"])
        thresholds = Thresholds(recipe_id=row["recipe_id"], **raw)
        return RecipeRecord(
            recipe_id=row["recipe_id"],
            digest=row["digest"],
            thresholds=thresholds,
        )

    def get_bundle(self, bundle_id: str) -> Bundle | None:
        row = self.query_one("SELECT * FROM bundles WHERE bundle_id=?", (bundle_id,))
        if row is None:
            return None
        calib_rows = self.query(
            "SELECT station_id, calib_id FROM bundle_calibs WHERE bundle_id=?",
            (bundle_id,),
        )
        return Bundle(
            bundle_id=row["bundle_id"],
            model_id=row["model_id"],
            recipe_id=row["recipe_id"],
            calibs={r["station_id"]: r["calib_id"] for r in calib_rows},
            created_by=row["created_by"],
            created_at=parse_ts(row["created_at"]),
        )

    def bundle_fingerprint(self, bundle_id: str) -> str | None:
        row = self.query_one("SELECT fingerprint FROM bundles WHERE bundle_id=?", (bundle_id,))
        return row["fingerprint"] if row else None

    def get_release(self, release_id: str) -> Release | None:
        row = self.query_one("SELECT * FROM releases WHERE release_id=?", (release_id,))
        if row is None:
            return None
        return Release(
            release_id=row["release_id"],
            bundle_id=row["bundle_id"],
            stations=tuple(json.loads(row["stations_json"])),
            created_by=row["created_by"],
            approved_by=row["approved_by"],
            approved_at=parse_ts(row["approved_at"]) if row["approved_at"] else None,
            frozen=bool(row["frozen"]),
            freeze_reason=row["freeze_reason"],
            created_at=parse_ts(row["created_at"]),
        )

    def find_release_for_combo(self, station_id: str, bundle_id: str) -> Release | None:
        rows = self.query(
            """SELECT release_id FROM stage_history
               WHERE station_id=? AND bundle_id=?
               ORDER BY started_at DESC LIMIT 1""",
            (station_id, bundle_id),
        )
        if not rows:
            return None
        return self.get_release(rows[0]["release_id"])

    # --- 工位状态与区间 --------------------------------------------------

    def get_station_state(self, station_id: str) -> StationState | None:
        row = self.query_one(
            "SELECT * FROM station_state WHERE station_id=?", (station_id,)
        )
        return self._station_from_row(row) if row else None

    def all_station_states(self) -> list[StationState]:
        return [self._station_from_row(r) for r in self.query(
            "SELECT * FROM station_state ORDER BY station_id"
        )]

    @staticmethod
    def _station_from_row(row: sqlite3.Row) -> StationState:
        return StationState(
            station_id=row["station_id"],
            release_id=row["release_id"],
            bundle_id=row["bundle_id"],
            stage=Stage(row["stage"]),
            confirmed=bool(row["confirmed"]),
            since=parse_ts(row["since"]),
        )

    def open_interval(
        self,
        station_id: str,
        release_id: str | None,
        bundle_id: str | None,
        stage: Stage,
        confirmed: bool,
        now: str,
    ) -> int:
        """关闭同工位未结束区间后开启新区间，返回新区间 id。"""

        self.execute(
            """UPDATE stage_history SET ended_at=?
               WHERE station_id=? AND ended_at IS NULL""",
            (now, station_id),
        )
        overlapping = self.query(
            """SELECT id FROM stage_history
               WHERE station_id=? AND started_at < ?
                 AND (ended_at IS NULL OR ended_at > ?)""",
            (station_id, now, now),
        )
        if overlapping:
            raise sqlite3.IntegrityError(
                f"工位 {station_id} 在 {now} 已存在生效区间"
            )
        cur = self.execute(
            """INSERT INTO stage_history
               (station_id, release_id, bundle_id, stage, confirmed, started_at)
               VALUES (?,?,?,?,?,?)""",
            (station_id, release_id, bundle_id, stage.value, int(confirmed), now),
        )
        return int(cur.lastrowid)

    def upsert_state(
        self,
        station_id: str,
        release_id: str | None,
        bundle_id: str | None,
        stage: Stage,
        confirmed: bool,
        now: str,
        history_id: int,
    ) -> None:
        self.execute(
            """INSERT INTO station_state
               (station_id, release_id, bundle_id, stage, confirmed, since, history_id)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(station_id) DO UPDATE SET
                 release_id=excluded.release_id,
                 bundle_id=excluded.bundle_id,
                 stage=excluded.stage,
                 confirmed=excluded.confirmed,
                 since=excluded.since,
                 history_id=excluded.history_id""",
            (station_id, release_id, bundle_id, stage.value, int(confirmed), now, history_id),
        )

    def mark_confirmed(self, station_id: str, history_id: int) -> None:
        self.execute(
            "UPDATE stage_history SET confirmed=1 WHERE id=?", (history_id,)
        )
        self.execute(
            "UPDATE station_state SET confirmed=1 WHERE station_id=?", (station_id,)
        )

    def interval_at(self, station_id: str, when: str) -> sqlite3.Row | None:
        return self.query_one(
            """SELECT * FROM stage_history
               WHERE station_id=? AND started_at<=?
                 AND (ended_at IS NULL OR ended_at>?)
               ORDER BY started_at DESC""",
            (station_id, when, when),
        )

    def intervals(self, station_id: str | None = None) -> list[StageInterval]:
        if station_id is None:
            rows = self.query(
                "SELECT * FROM stage_history ORDER BY station_id, started_at"
            )
        else:
            rows = self.query(
                "SELECT * FROM stage_history WHERE station_id=? ORDER BY started_at",
                (station_id,),
            )
        return [
            StageInterval(
                station_id=r["station_id"],
                bundle_id=r["bundle_id"],
                stage=Stage(r["stage"]),
                started_at=parse_ts(r["started_at"]),
                ended_at=parse_ts(r["ended_at"]) if r["ended_at"] else None,
                confirmed=bool(r["confirmed"]),
            )
            for r in rows
        ]

    # --- 批次 ------------------------------------------------------------

    def get_seal(self, batch_id: str) -> tuple[str, dict[str, Any], tuple[str, ...]] | None:
        row = self.query_one("SELECT * FROM batch_seals WHERE batch_id=?", (batch_id,))
        if row is None:
            return None
        return (
            row["sealed_at"],
            json.loads(row["stats_json"]),
            tuple(json.loads(row["receipt_ids_json"])),
        )

    def evidence(self, release_id: str) -> list[sqlite3.Row]:
        return self.query(
            "SELECT * FROM rollback_evidence WHERE release_id=? ORDER BY id",
            (release_id,),
        )
