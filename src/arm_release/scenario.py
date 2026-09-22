"""随附换线事故场景的构建器。

生成一份完全自包含的事件场景：内嵌签名公钥（JWK）、用临时私钥
为模型与推理回执签名，私钥只存在于构建进程，不进入版本库。
质量人员无需任何外部资料即可重放：

    python -m arm_release.cli build-incident --out fixtures/incident_line_change.json
    python -m arm_release.cli replay fixtures/incident_line_change.json
"""

from __future__ import annotations

from typing import Any

from .crypto import RsaPrivateKey, generate_rsa, sha256_bytes
from .domain import (
    Receipt,
    SampleInput,
    Thresholds,
    b64e,
    canonical_json,
)

STATIONS = ("arm-cell-01", "arm-cell-02", "arm-cell-03")
RECIPE = "housing-a17"


def _envelope(index: int, kind: str, occurred: str, received: str,
              attributes: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": f"a17-{index:03d}",
        "kind": kind,
        "occurred_at": occurred,
        "received_at": received,
        "attributes": attributes,
    }


def _sign_model(key: RsaPrivateKey, model_id: str, payload: bytes) -> tuple[str, str]:
    digest = sha256_bytes(payload)
    message = canonical_json(["model@v1", model_id, digest])
    return digest, b64e(key.sign(message))


def _signed_receipt(
    key: RsaPrivateKey, index_seq: list[int],
    receipt_id: str, station: str, bundle: str, occurred: str, received: str,
    samples: list[tuple[str, bool, bool, float]],
    batch_id: str | None = None,
) -> dict[str, Any]:
    receipt = Receipt(
        receipt_id=receipt_id,
        station_id=station,
        bundle_id=bundle,
        occurred_at=_parse(occurred),
        received_at=_parse(received),
        samples=[
            SampleInput(sample_id=s, is_defect=d, model_reject=r, latency_ms=lat)
            for s, d, r, lat in samples
        ],
        batch_id=batch_id,
        key_id="factory-root-2026",
    )
    index_seq[0] += 1
    attrs: dict[str, Any] = {
        "receipt_id": receipt_id,
        "station_id": station,
        "bundle_id": bundle,
        "occurred_at": occurred,
        "received_at": received,
        "samples": [
            {"sample_id": s, "is_defect": d, "model_reject": r, "latency_ms": lat}
            for s, d, r, lat in samples
        ],
        "key_id": "factory-root-2026",
        "signature": b64e(key.sign(receipt.signing_message())),
    }
    if batch_id:
        attrs["batch_id"] = batch_id
    return _envelope(index_seq[0], "inference_reported", occurred, received, attrs)


def _parse(value: str):
    from .domain import parse_ts

    return parse_ts(value)


def build_incident(bits: int = 2048) -> dict[str, Any]:
    """返回 2026-09-10 换线事故的完整事件场景。"""

    key = generate_rsa(bits)
    events: list[dict[str, Any]] = []
    seq = [0]

    def add(kind: str, occurred: str, received: str | None = None,
            **attrs: Any) -> None:
        seq[0] += 1
        events.append(_envelope(
            seq[0], kind, occurred, received or _plus_minute(occurred), attrs
        ))

    # 1) 信任根与资产 -----------------------------------------------------
    add("signing_key_registered", "2026-09-10T07:30:00+08:00",
        key_id="factory-root-2026", jwk=key.public.to_jwk())

    v7_payload = b"vision-model v7 weights"
    v8_payload = b"vision-model v8 weights"
    d7, s7 = _sign_model(key, "vision-v7", v7_payload)
    d8, s8 = _sign_model(key, "vision-v8", v8_payload)
    add("model_registered", "2026-09-10T07:31:00+08:00",
        model_id="vision-v7", digest=d7, signature=s7,
        key_id="factory-root-2026", created_by="ml-eng.chen")
    add("model_registered", "2026-09-10T07:32:00+08:00",
        model_id="vision-v8", digest=d8, signature=s8,
        key_id="factory-root-2026", created_by="ml-eng.chen")

    for station in STATIONS:
        n = station[-2:]
        add("calibration_registered", f"2026-09-10T07:33:00+08:00",
            calib_id=f"cal-{n}", station_id=station,
            digest=f"sha256:cal-{n}-v1", created_by="vision-optics")
        add("calibration_registered", f"2026-09-10T07:34:00+08:00",
            calib_id=f"cal-{n}-v2", station_id=station,
            digest=f"sha256:cal-{n}-v2", created_by="vision-optics")

    thresholds = Thresholds(
        recipe_id=RECIPE,
        min_recall=0.99,
        max_false_reject_rate=0.02,
        max_latency_ms=120.0,
        min_decision_samples=60,
        canary_cap=200,
    )
    add("recipe_registered", "2026-09-10T07:35:00+08:00",
        recipe_id=RECIPE, created_by="quality-head.li",
        thresholds={
            "min_recall": thresholds.min_recall,
            "max_false_reject_rate": thresholds.max_false_reject_rate,
            "max_latency_ms": thresholds.max_latency_ms,
            "min_decision_samples": thresholds.min_decision_samples,
            "canary_cap": thresholds.canary_cap,
        })

    add("bundle_registered", "2026-09-10T07:40:00+08:00",
        bundle_id="B-stable-v7", model_id="vision-v7", recipe_id=RECIPE,
        calibs={s: f"cal-{s[-2:]}" for s in STATIONS},
        created_by="release-eng.zhao")
    add("bundle_registered", "2026-09-10T07:42:00+08:00",
        bundle_id="B-candidate-v8", model_id="vision-v8", recipe_id=RECIPE,
        calibs={s: f"cal-{s[-2:]}-v2" for s in STATIONS},
        created_by="release-eng.zhao")

    # 2) 基线在役 + 上午生产 ---------------------------------------------
    for station in STATIONS:
        add("stable_provisioned", "2026-09-10T08:00:00+08:00",
            station_id=station, bundle_id="B-stable-v7", actor="line-lead.wang")

    def good_window(prefix: str, n: int) -> list[tuple[str, bool, bool, float]]:
        rows: list[tuple[str, bool, bool, float]] = []
        for i in range(n):
            defect = (i % 11 == 0)
            rows.append((f"{prefix}-{i:03d}", defect, defect,
                         55.0 + (i % 7)))
        return rows

    for station in STATIONS:
        events.append(_signed_receipt(
            key, seq, f"rcp-{station[-2:]}-morning-A", station,
            "B-stable-v7", "2026-09-10T08:20:00+08:00",
            "2026-09-10T08:21:00+08:00", good_window(f"{station}-A", 30),
            batch_id="B20260910-A",
        ))
    for station in STATIONS:
        events.append(_signed_receipt(
            key, seq, f"rcp-{station[-2:]}-morning-B", station,
            "B-stable-v7", "2026-09-10T08:40:00+08:00",
            "2026-09-10T08:41:00+08:00", good_window(f"{station}-B", 20),
            batch_id="B20260910-B",
        ))

    add("batch_sealed", "2026-09-10T09:00:00+08:00",
        batch_id="B20260910-A", actor="quality-head.li")

    # 3) 新组合发布：创建人与审批人不同 -----------------------------------
    add("release_created", "2026-09-10T09:20:00+08:00",
        release_id="R-v8-rollout", bundle_id="B-candidate-v8",
        stations=list(STATIONS), created_by="release-eng.zhao")
    add("release_approved", "2026-09-10T09:25:00+08:00",
        release_id="R-v8-rollout", approver="quality-head.li")

    # 4) 影子比对：候选不外发，在役仍是 v7 --------------------------------
    for station in STATIONS:
        add("shadow_started", "2026-09-10T09:30:00+08:00",
            release_id="R-v8-rollout", station_id=station, actor="line-lead.wang")
    for station in STATIONS:
        for i in range(6):
            defect = i == 5
            incumbent = defect
            candidate = defect and i != 5  # 候选对最后一件缺陷漏判
            add("shadow_observed", "2026-09-10T09:35:00+08:00",
                release_id="R-v8-rollout", station_id=station,
                sample_id=f"sh-{station[-2:]}-{i}",
                is_defect=defect, incumbent_reject=incumbent,
                candidate_reject=bool(candidate), latency_ms=70.0 + i)

    # 5) 限量试运行；01、02 已现场确认，03 尚未确认 ------------------------
    for station in STATIONS:
        add("canary_started", "2026-09-10T09:40:00+08:00",
            release_id="R-v8-rollout", station_id=station,
            operator="line-lead.wang")
    add("station_acknowledged", "2026-09-10T09:46:00+08:00",
        release_id="R-v8-rollout", station_id="arm-cell-01",
        operator="op.zhou")
    add("station_acknowledged", "2026-09-10T09:47:00+08:00",
        release_id="R-v8-rollout", station_id="arm-cell-02",
        operator="op.zhou")

    # 批次 B 在补数到达前封存（封存统计随后不得变化）。
    add("batch_sealed", "2026-09-10T09:50:00+08:00",
        batch_id="B20260910-B", actor="quality-head.li")

    # 6) 限量数据：01、02 健康；03 误剔除率显著升高 -----------------------
    events.append(_signed_receipt(
        key, seq, "rcp-01-canary-1", "arm-cell-01", "B-candidate-v8",
        "2026-09-10T09:50:00+08:00", "2026-09-10T09:51:00+08:00",
        _canary_healthy("c01", 24),
    ))
    events.append(_signed_receipt(
        key, seq, "rcp-02-canary-1", "arm-cell-02", "B-candidate-v8",
        "2026-09-10T09:52:00+08:00", "2026-09-10T09:53:00+08:00",
        _canary_healthy("c02", 24),
    ))
    events.append(_signed_receipt(
        key, seq, "rcp-03-canary-1", "arm-cell-03", "B-candidate-v8",
        "2026-09-10T10:02:00+08:00", "2026-09-10T10:20:00+08:00",  # 断网迟到
        _canary_false_rejects("c03", 24),
    ))

    # 7) 断网重连后重复回执：只计一次 -------------------------------------
    dup = _signed_receipt(
        key, seq, "rcp-03-canary-1", "arm-cell-03", "B-candidate-v8",
        "2026-09-10T10:02:00+08:00", "2026-09-10T10:21:00+08:00",
        _canary_false_rejects("c03", 24),
    )
    dup["event_id"] = "a17-900"
    events.append(dup)

    # 8) 回滚后现场确认已恢复 v7 ------------------------------------------
    add("restored_confirmed", "2026-09-10T10:25:00+08:00",
        station_id="arm-cell-03", operator="op.zhou")

    # 9) 已封存批次 B 的迟到补数：只做补充，不改统计 -----------------------
    events.append(_signed_receipt(
        key, seq, "rcp-02-morning-B-late", "arm-cell-02", "B-stable-v7",
        "2026-09-10T08:45:00+08:00", "2026-09-10T10:28:00+08:00",
        good_window("c02-B-late", 10),
        batch_id="B20260910-B",
    ))

    # 10) 回滚生效后仍声称候选组合的回执：拒绝归属 ------------------------
    forged = _signed_receipt(
        key, seq, "rcp-03-after-rollback", "arm-cell-03", "B-candidate-v8",
        "2026-09-10T10:30:00+08:00", "2026-09-10T10:31:00+08:00",
        _canary_false_rejects("c03x", 5),
    )
    forged["event_id"] = "a17-901"
    events.append(forged)

    events.sort(key=lambda e: (e["occurred_at"], e["event_id"]))
    return {"scenario": "line-change-a17-full", "events": events}


def _plus_minute(value: str) -> str:
    from datetime import timedelta

    parsed = _parse(value)
    moved = parsed + timedelta(minutes=1)
    return moved.isoformat()


def _canary_healthy(prefix: str, n: int) -> list[tuple[str, bool, bool, float]]:
    rows: list[tuple[str, bool, bool, float]] = []
    for i in range(n):
        defect = i in (3, 17)
        rows.append((f"{prefix}-{i:03d}", defect, defect, 60.0 + (i % 5)))
    return rows


def _canary_false_rejects(prefix: str, n: int) -> list[tuple[str, bool, bool, float]]:
    """24 件中 2 件缺陷均被捕获，但 22 件良品中 4 件被误剔除（18%）。"""

    rows: list[tuple[str, bool, bool, float]] = []
    false_reject_idx = {1, 8, 13, 20}
    for i in range(n):
        defect = i in (3, 17)
        reject = defect or (i in false_reject_idx)
        rows.append((f"{prefix}-{i:03d}", defect, reject, 88.0 + (i % 4)))
    return rows
