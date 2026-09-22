"""命令行入口。

示例：
    python -m arm_release demo --db data/demo.sqlite3
    python -m arm_release replay --db data/demo.sqlite3
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .crypto import PublicKey, SigningKey
from .models import PlatformError, Thresholds
from .platform import GateConfig, Platform
from .replay import evidence_samples, replay
from .store import Store


def _load_json(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _print(data: Any) -> None:
    json.dump(data, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def _platform(args: argparse.Namespace) -> Platform:
    store = Store.open(args.db)
    return Platform(store)


def cmd_keygen(args: argparse.Namespace) -> None:
    key = SigningKey.generate(args.kid)
    out = Path(args.out)
    out.write_text(
        json.dumps(key.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    if args.public_out:
        Path(args.public_out).write_text(
            json.dumps(key.public().to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    print(f"私钥已写入 {out}（请勿提交版本库）")


def cmd_add_key(args: argparse.Namespace) -> None:
    doc = _load_json(args.key_file)
    pub = PublicKey.from_dict(doc)
    platform = _platform(args)
    platform.add_trusted_key(pub, args.role)
    print(f"已信任密钥 {pub.kid}（角色 {args.role}）")


def cmd_register_model(args: argparse.Namespace) -> None:
    platform = _platform(args)
    ref = platform.register_model(_load_json(args.envelope))
    print(f"模型已登记：{ref}")


def cmd_register_calibration(args: argparse.Namespace) -> None:
    platform = _platform(args)
    print("标定快照已登记：" + platform.register_calibration(_load_json(args.envelope)))


def cmd_register_recipe(args: argparse.Namespace) -> None:
    doc = _load_json(args.envelope)
    platform = _platform(args)
    platform.register_recipe(
        doc["recipe"],
        doc["version"],
        Thresholds.from_dict(doc["thresholds"]),
    )
    print(f"配方已登记：{doc['recipe']}@{doc['version']}")


def cmd_register_bundle(args: argparse.Namespace) -> None:
    platform = _platform(args)
    bundle_id = platform.register_bundle(_load_json(args.envelope))
    print(f"发布组合已登记：{bundle_id}")


def cmd_approve(args: argparse.Namespace) -> None:
    platform = _platform(args)
    platform.approve_bundle(args.bundle_id, args.approver)
    print(f"组合 {args.bundle_id} 已由 {args.approver} 审批")


def cmd_stable(args: argparse.Namespace) -> None:
    platform = _platform(args)
    platform.establish_stable(args.station, args.bundle_id, args.at)
    print(f"{args.station} 在役稳定组合：{args.bundle_id}")


def cmd_shadow(args: argparse.Namespace) -> None:
    platform = _platform(args)
    platform.start_shadow(args.station, args.bundle_id, args.executor)
    print(f"{args.station} 进入影子比对：{args.bundle_id}")


def cmd_promote(args: argparse.Namespace) -> None:
    platform = _platform(args)
    phase = platform.promote(args.station, args.bundle_id, args.executor)
    print(f"{args.station} 已推进到 {phase}")


def cmd_receipt(args: argparse.Namespace) -> None:
    platform = _platform(args)
    result = platform.report_receipt(_load_json(args.envelope))
    _print(result.__dict__)


def cmd_freeze(args: argparse.Namespace) -> None:
    platform = _platform(args)
    reason = _load_json(args.reason_file) if args.reason_file else {"manual": True}
    platform.freeze(args.bundle_id, reason, args.actor)
    print(f"组合 {args.bundle_id} 已冻结，未确认工位已退回上一稳定组合")


def cmd_seal(args: argparse.Namespace) -> None:
    platform = _platform(args)
    _print(platform.seal_batch(args.batch_id))


def cmd_batch_summary(args: argparse.Namespace) -> None:
    platform = _platform(args)
    _print(platform.sealed_batch_summary(args.batch_id))


def cmd_status(args: argparse.Namespace) -> None:
    platform = _platform(args)
    _print(platform.station_status(args.station))


def cmd_serving(args: argparse.Namespace) -> None:
    platform = _platform(args)
    _print(platform.serving_view(args.station))


def cmd_replay(args: argparse.Namespace) -> None:
    store = Store.open(args.db)
    report = replay(store)
    report["evidence_samples"] = evidence_samples(store, report)
    _print(report)


def cmd_demo(args: argparse.Namespace) -> None:
    from .demo_incident import build_demo

    report = build_demo(args.db, restart_midway=not args.no_restart)
    _print(report)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="arm_release", description="机械臂视觉模型放行平台")
    parser.add_argument("--db", default="data/platform.sqlite3", help="SQLite 数据库路径")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="生成 Ed25519 密钥（演示用）")
    p.add_argument("--kid", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--public-out")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("add-key", help="登记受信任公钥")
    p.add_argument("key_file")
    p.add_argument("--role", choices=("model", "release"), required=True)
    p.set_defaults(func=cmd_add_key)

    p = sub.add_parser("register-model", help="验签登记模型")
    p.add_argument("envelope")
    p.set_defaults(func=cmd_register_model)

    p = sub.add_parser("register-calibration", help="登记标定快照")
    p.add_argument("envelope")
    p.set_defaults(func=cmd_register_calibration)

    p = sub.add_parser("register-recipe", help="登记产品配方门槛")
    p.add_argument("envelope")
    p.set_defaults(func=cmd_register_recipe)

    p = sub.add_parser("register-bundle", help="验签登记发布组合")
    p.add_argument("envelope")
    p.set_defaults(func=cmd_register_bundle)

    p = sub.add_parser("approve", help="质量审批组合")
    p.add_argument("bundle_id")
    p.add_argument("--by", dest="approver", required=True)
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("stable", help="登记工位在役稳定组合")
    p.add_argument("station")
    p.add_argument("bundle_id")
    p.add_argument("--at")
    p.set_defaults(func=cmd_stable)

    p = sub.add_parser("shadow", help="工位进入影子比对")
    p.add_argument("station")
    p.add_argument("bundle_id")
    p.add_argument("--executor", required=True)
    p.set_defaults(func=cmd_shadow)

    p = sub.add_parser("promote", help="推进到下一发布阶段")
    p.add_argument("station")
    p.add_argument("bundle_id")
    p.add_argument("--executor", required=True)
    p.set_defaults(func=cmd_promote)

    p = sub.add_parser("receipt", help="接入一条推理回执")
    p.add_argument("envelope")
    p.set_defaults(func=cmd_receipt)

    p = sub.add_parser("freeze", help="手动冻结扩围并回滚未确认工位")
    p.add_argument("bundle_id")
    p.add_argument("--by", dest="actor", required=True)
    p.add_argument("--reason-file")
    p.set_defaults(func=cmd_freeze)

    p = sub.add_parser("seal", help="封存生产批次统计")
    p.add_argument("batch_id")
    p.set_defaults(func=cmd_seal)

    p = sub.add_parser("batch-summary", help="查看封存批次统计（不可变）")
    p.add_argument("batch_id")
    p.set_defaults(func=cmd_batch_summary)

    p = sub.add_parser("status", help="查看工位发布状态")
    p.add_argument("station")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("serving", help="查看机械臂在役下发视图")
    p.add_argument("station")
    p.set_defaults(func=cmd_serving)

    p = sub.add_parser("replay", help="重放事件流，输出事故报告")
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("demo", help="构建并复现换线事故 a17")
    p.add_argument("--no-restart", action="store_true", help="不模拟服务重启")
    p.set_defaults(func=cmd_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (PlatformError, FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
