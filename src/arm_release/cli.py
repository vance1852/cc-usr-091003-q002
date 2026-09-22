"""命令行入口：构建事故场景、重放取证、查看放行状态。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .contracts import load_events
from .projector import EventProjector
from .replay import Forensics
from .scenario import build_incident
from .service import ReleasePlatform
from .store import Store


def _open(path: str) -> Store:
    store = Store(path)
    return store


def cmd_build_incident(args: argparse.Namespace) -> int:
    scenario = build_incident()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(scenario, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"已写入事故场景 {out}（{len(scenario['events'])} 个事件，签名自包含）")
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    scenario, events = load_events(args.scenario)
    store = _open(args.db)
    try:
        platform = ReleasePlatform(store)
        projector = EventProjector(platform)
        stats = projector.replay(events)
        forensics = Forensics(store)
        if args.json:
            report = forensics.report()
            report["projection"] = {
                "scenario": scenario,
                "applied": stats.applied,
                "skipped": stats.skipped,
                "dead_lettered": stats.dead_lettered,
                "outcomes": stats.outcomes,
            }
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print(f"场景 {scenario}：新应用 {stats.applied}，"
                  f"已应用跳过 {stats.skipped}，隔离 {stats.dead_lettered}")
            print(forensics.render_text())
            dead = store.query("SELECT * FROM projection_dead_letter ORDER BY event_id")
            if dead:
                print("")
                print("== 被拒绝并隔离的事件（证据，不参与统计） ==")
                for row in dead:
                    print(f"- {row['event_id']}（{row['kind']}）：{row['error']}")
        return 0
    finally:
        store.close()


def cmd_status(args: argparse.Namespace) -> int:
    store = _open(args.db)
    try:
        rows = store.query(
            """SELECT station_id, release_id, bundle_id, stage, confirmed, since
               FROM station_state ORDER BY station_id"""
        )
        if not rows:
            print("（无工位状态）")
            return 0
        for row in rows:
            flag = "已确认" if row["confirmed"] else "未确认"
            print(
                f"{row['station_id']:<12} {row['stage']:<11} "
                f"组合 {row['bundle_id']:<16} 发布 {row['release_id'] or '-'} "
                f"[{flag}] 自 {row['since']}"
            )
        frozen = store.query("SELECT release_id, freeze_reason FROM releases WHERE frozen=1")
        for row in frozen:
            print(f"冻结发布 {row['release_id']}：{row['freeze_reason']}")
        return 0
    finally:
        store.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="arm_release", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_build = sub.add_parser("build-incident", help="生成自包含换线事故场景")
    p_build.add_argument("--out", required=True)
    p_build.set_defaults(func=cmd_build_incident)

    p_replay = sub.add_parser("replay", help="重放事件场景并输出取证报告")
    p_replay.add_argument("scenario")
    p_replay.add_argument("--db", default=":memory:", help="SQLite 路径，默认内存")
    p_replay.add_argument("--json", action="store_true", help="输出 JSON 报告")
    p_replay.set_defaults(func=cmd_replay)

    p_status = sub.add_parser("status", help="查看工位阶段状态")
    p_status.add_argument("--db", required=True)
    p_status.set_defaults(func=cmd_status)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
