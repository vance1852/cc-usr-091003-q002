"""换线事故 line-change-a17 的确定性复现。

时间线（UTC+8）：
  08:00 三座工位在役稳定组合 B0（旧模型 + 旧标定，配方 housing-a17 v3）
  09:00 候选组合 B1（新模型 + 新标定）进入影子比对
  09:20 影子门槛通过，限量试运行
  10:00 新品换线，三座工位进入扩围
  11:00 封存早班批次 L42-morning
  11:30 服务在扩围中途重启
  11:55 arm-cell-03 断网，回执滞留现场
  12:05 arm-cell-03 误剔除越界，触发冻结，三座工位全部退回 B0
  12:20 网络恢复，迟到回执按实际发生时刻归位；重复回执只计一次
  12:25 已封存批次的补数被隔离，封存统计不变
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .crypto import (
    PublicKey,
    SigningKey,
    sha256_digest,
    sign_payload,
)
from .models import Thresholds
from .platform import GateConfig, GateRequirement, Platform
from .replay import evidence_samples, replay
from .store import Store

TZ = timezone(timedelta(hours=8))
STATIONS = ["arm-cell-01", "arm-cell-02", "arm-cell-03"]


class _Clock:
    def __init__(self, t: datetime):
        self.t = t

    def set(self, t: datetime) -> None:
        self.t = t

    def __call__(self) -> datetime:
        return self.t


def _dt(h: int, m: int = 0, day: int = 10) -> datetime:
    return datetime(2026, 9, day, h, m, tzinfo=TZ)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _signed_model(key: SigningKey, model_id: str, version: str, blob: bytes) -> dict[str, Any]:
    digest = sha256_digest(blob)
    payload = {
        "model_id": model_id,
        "version": version,
        "digest": digest,
        "media_type": "application/octet-stream",
        "size": len(blob),
    }
    return {
        "model_id": model_id,
        "version": version,
        "digest": digest,
        "kid": key.kid,
        "signature": sign_payload(key, payload),
        "payload": payload,
    }


def _calibration(snapshot_id: str, camera_id: str, at: datetime) -> dict[str, Any]:
    body = {
        "snapshot_id": snapshot_id,
        "camera_id": camera_id,
        "taken_at": _iso(at),
        "intrinsics": {"fx": 1720.4, "fy": 1718.9, "cx": 968.1, "cy": 612.7, "rms": 0.21},
    }
    body["digest"] = sha256_digest(
        json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")
    )
    return body


def _signed_bundle(
    release_key: SigningKey,
    bundle_id: str,
    model: dict[str, Any],
    calibration: dict[str, Any],
    recipe: str,
    recipe_version: str,
) -> dict[str, Any]:
    manifest = {
        "bundle_id": bundle_id,
        "recipe": recipe,
        "recipe_version": recipe_version,
        "model": {
            "model_id": model["model_id"],
            "version": model["version"],
            "digest": model["digest"],
        },
        "calibration": {
            "snapshot_id": calibration["snapshot_id"],
            "camera_id": calibration["camera_id"],
            "digest": calibration["digest"],
        },
    }
    return {
        "bundle_id": bundle_id,
        "kid": release_key.kid,
        "signature": sign_payload(release_key, manifest),
        "parts": {
            "model": {"model_id": model["model_id"], "version": model["version"]},
            "calibration": {"snapshot_id": calibration["snapshot_id"]},
            "recipe": recipe,
            "recipe_version": recipe_version,
            "manifest": manifest,
        },
    }


def _receipt(
    rid: str,
    station: str,
    bundle_id: str,
    occurred: datetime,
    *,
    truth: str,
    decision: str,
    latency_ms: float,
    received: datetime | None = None,
    champion_decision: str | None = None,
    batch_id: str | None = None,
) -> dict[str, Any]:
    out = {
        "receipt_id": rid,
        "station_id": station,
        "bundle_id": bundle_id,
        "occurred_at": _iso(occurred),
        "received_at": _iso(received or occurred),
        "truth": truth,
        "decision": decision,
        "latency_ms": latency_ms,
    }
    if champion_decision is not None:
        out["champion_decision"] = champion_decision
    if batch_id is not None:
        out["batch_id"] = batch_id
    return out


def build_demo(db_path: str | Path, restart_midway: bool = True) -> dict[str, Any]:
    path = Path(db_path)
    if path.exists():
        path.unlink()
    for suffix in ("-wal", "-shm"):
        side = path.with_name(path.name + suffix)
        if side.exists():
            side.unlink()

    clock = _Clock(_dt(8))
    gates = GateConfig(
        shadow=GateRequirement(min_samples=6, min_shadow_pairs=6),
        canary=GateRequirement(min_samples=8),
        rollout=GateRequirement(min_samples=10),
    )
    store = Store.open(path)
    pf = Platform(store, gates=gates, clock=clock)

    # ---- 信任根：工厂签名公钥清单 ------------------------------------
    model_key = SigningKey.generate(kid="k-factory-model-2026")
    release_key = SigningKey.generate(kid="k-factory-release-2026")
    pf.add_trusted_key(model_key.public(), role="model")
    pf.add_trusted_key(release_key.public(), role="release")

    # ---- 产品配方门槛 ------------------------------------------------
    thresholds = Thresholds(
        min_defect_recall=0.98,
        max_false_reject_rate=0.02,
        max_latency_p95_ms=120.0,
    )
    pf.register_recipe("housing-a17", "3", thresholds)

    # ---- 在役稳定组合 B0 ---------------------------------------------
    old_model = _signed_model(
        model_key, "housing-vision", "2026.08.01", b"OLD-MODEL-WEIGHTS"
    )
    old_cal = _calibration("cal-line-a17-0828", "cam-line-a17", _dt(8) - timedelta(days=13))
    pf.register_model(old_model)
    pf.register_calibration(old_cal)
    b0 = _signed_bundle(
        release_key, "B0", old_model, old_cal, "housing-a17", "3"
    )
    pf.register_bundle(b0)
    clock.set(_dt(7, 50))
    pf.approve_bundle("B0", "qa-lead.chen")
    for station in STATIONS:
        pf.establish_stable(station, "B0", at=_iso(_dt(8)))

    # ---- 候选组合 B1：新模型 + 新标定，同一配方 ------------------------
    new_model = _signed_model(
        model_key, "housing-vision", "2026.09.10", b"NEW-MODEL-WEIGHTS-A17"
    )
    new_cal = _calibration("cal-line-a17-0910", "cam-line-a17", _dt(8, 30))
    pf.register_model(new_model)
    pf.register_calibration(new_cal)
    b1 = _signed_bundle(
        release_key, "B1", new_model, new_cal, "housing-a17", "3"
    )
    clock.set(_dt(8, 55))
    pf.register_bundle(b1)
    # 审批人 qa-lead.chen；执行人必须是另一个人 ops-eng.li
    pf.approve_bundle("B1", "qa-lead.chen")

    # ---- 影子比对（候选不驱动机械臂）---------------------------------
    clock.set(_dt(9))
    for station in STATIONS:
        pf.start_shadow(station, "B1", executor="ops-eng.li")

    def shadow_stream(station: str) -> None:
        # 6 个配对：候选与在役判定一致，2 个缺陷全部抓出
        plan = [
            ("good", "accept"),
            ("defect", "reject"),
            ("good", "accept"),
            ("good", "accept"),
            ("defect", "reject"),
            ("good", "accept"),
        ]
        for i, (truth, decision) in enumerate(plan):
            occurred = _dt(9, 2 + i)
            rid = f"r-{station}-sh-{i}"
            batch = "L42-morning" if i < 4 else None
            res = pf.report_receipt(
                _receipt(
                    rid, station, "B1", occurred,
                    truth=truth, decision=decision, latency_ms=58 + i,
                    champion_decision=decision, batch_id=batch,
                )
            )
            assert res.outcome == "counted", (rid, res)

    for station in STATIONS:
        shadow_stream(station)

    # ---- 限量试运行 ---------------------------------------------------
    clock.set(_dt(9, 20))
    for station in STATIONS:
        assert pf.promote(station, "B1", "ops-eng.li") == "canary"

    def healthy_stream(station: str, start_min: int, tag: str, n: int = 8) -> None:
        plan = (
            [("good", "accept")] * 4
            + [("defect", "reject")]
            + [("good", "accept")] * 3
        )[:n]
        for i, (truth, decision) in enumerate(plan):
            occurred = _dt(9, start_min + i * 4)
            batch = "L42-morning" if occurred < _dt(11) else None
            res = pf.report_receipt(
                _receipt(
                    f"r-{station}-{tag}-{i}", station, "B1", occurred,
                    truth=truth, decision=decision, latency_ms=62 + (i % 5),
                    batch_id=batch,
                )
            )
            assert res.outcome == "counted", res.quarantine_reason

    for station in STATIONS:
        healthy_stream(station, 25, "ca")

    # ---- 新品换线，进入扩围 -------------------------------------------
    clock.set(_dt(10))
    for station in STATIONS:
        assert pf.promote(station, "B1", "ops-eng.li") == "rollout"

    def rollout_healthy(station: str, times) -> None:
        # 含 2 个缺陷全抓，其余良品全部放行
        times = list(times)
        defect_idx = {2, 6}
        for i, occurred in enumerate(times):
            truth = "defect" if i in defect_idx else "good"
            decision = "reject" if truth == "defect" else "accept"
            res = pf.report_receipt(
                _receipt(
                    f"r-{station}-ro-{i}", station, "B1", occurred,
                    truth=truth, decision=decision, latency_ms=70 + (i % 4),
                )
            )
            assert res.outcome == "counted", res.quarantine_reason

    # 每座工位 9 条扩围健康样本（10:05–11:48）
    rollout_times = [_dt(10) + timedelta(minutes=m) for m in (5, 18, 32, 46, 59, 72, 84, 96, 108)]
    for station in STATIONS:
        rollout_healthy(station, rollout_times)

    # ---- 11:00 封存早班批次 -------------------------------------------
    clock.set(_dt(11))
    sealed_summary = pf.seal_batch("L42-morning")
    sealed_before = json.dumps(sealed_summary, sort_keys=True, ensure_ascii=False)

    # ---- 扩围中途重启：重新打开库，状态必须保持单工位单阶段 -------------
    post_restart: dict[str, Any] = {}
    if restart_midway:
        store.close()
        store = Store.open(path)
        pf = Platform(store, gates=gates, clock=clock)
        for station in STATIONS:
            status = pf.station_status(station)
            assert status["pipeline"]["bundle_id"] == "B1"
            assert status["pipeline"]["phase"] == "rollout"
            assert status["stable_bundle"] == "B0"
            post_restart[station] = status
        assert pf.serving_view("arm-cell-02")["arm_serves"]["bundle_id"] == "B1"

    # ---- 11:55 arm-cell-03 断网前产生的健康回执，先不报送 --------------
    late = _receipt(
        "r-arm-cell-03-late", "arm-cell-03", "B1", _dt(11, 55),
        truth="good", decision="accept", latency_ms=74,
        received=_dt(12, 20),
    )

    # ---- 12:05 误剔除率飙升：良品被判废，第 10 条扩围样本即越界 ---------
    clock.set(_dt(12, 5))
    trigger = _receipt(
        "r-arm-cell-03-trigger", "arm-cell-03", "B1", _dt(12, 5),
        truth="good", decision="reject", latency_ms=81,
    )
    trigger_res = pf.report_receipt(trigger)
    assert trigger_res.outcome == "counted"
    assert trigger_res.triggered_freeze is True
    assert pf.is_frozen("B1")

    # 冻结后禁止继续推进
    blocked = False
    try:
        pf.promote("arm-cell-01", "B1", "ops-eng.li")
    except Exception:
        blocked = True
    assert blocked

    # 三座未确认工位全部退回 B0；机械臂视图恢复在役旧组合
    for station in STATIONS:
        status = pf.station_status(station)
        assert status["pipeline"] is None
        assert status["stable_bundle"] == "B0"
        assert pf.serving_view(station)["arm_serves"]["bundle_id"] == "B0"

    # ---- 12:20 网络恢复：迟到回执归位到实际执行的 B1 扩围区间 ----------
    clock.set(_dt(12, 20))
    late_res = pf.report_receipt(late)
    assert late_res.outcome == "counted"
    assert late_res.counted_phase == "rollout"

    # 同一回执再次报送（重传）：只计一次
    dup_res = pf.report_receipt(dict(late))
    assert dup_res.outcome == "duplicate"

    # 12:10（回滚之后）才产生的 B1 判定回执：B1 当时已不在役，隔离
    stray = _receipt(
        "r-arm-cell-03-stray", "arm-cell-03", "B1", _dt(12, 10),
        truth="good", decision="reject", latency_ms=88,
        received=_dt(12, 21),
    )
    stray_res = pf.report_receipt(stray)
    assert stray_res.outcome == "quarantined"

    # ---- 12:25 已封存批次补数：隔离留证，统计不变 ----------------------
    clock.set(_dt(12, 25))
    backfill = _receipt(
        "r-sealed-backfill", "arm-cell-01", "B1", _dt(10, 30),
        truth="good", decision="reject", latency_ms=200,
        received=_dt(12, 25), batch_id="L42-morning",
    )
    backfill_res = pf.report_receipt(backfill)
    assert backfill_res.outcome == "quarantined"
    assert backfill_res.quarantine_reason == "batch_sealed_late_backfill"
    sealed_after = json.dumps(
        pf.sealed_batch_summary("L42-morning"), sort_keys=True, ensure_ascii=False
    )
    assert sealed_after == sealed_before

    # ---- 重放事故 -----------------------------------------------------
    report = replay(store)
    report["scenario"] = "line-change-a17"
    report["evidence_samples"] = evidence_samples(store, report)
    report["late_receipt"] = late_res.__dict__
    report["duplicate_receipt"] = dup_res.__dict__
    report["stray_receipt"] = stray_res.__dict__
    report["sealed_backfill"] = backfill_res.__dict__
    report["sealed_summary_unchanged"] = sealed_after == sealed_before
    report["restart_invariant_held"] = bool(post_restart) or not restart_midway
    report["serving_after_rollback"] = {
        station: pf.serving_view(station)["arm_serves"]["bundle_id"]
        for station in STATIONS
    }
    store.close()
    return report
