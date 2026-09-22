# 机械臂视觉模型换线放行平台

机械臂工位以**发布组合**绑定视觉模型、相机标定与产品配方。平台在换线时
强制「影子比对 → 限量试运行 → 扩围」三段放行，用缺陷召回、误剔除率、
推理时延三道安全门槛控制扩围，并对断网迟到、重复回执、批次封存补数、
扩围中途重启等现场情况给出确定性处理。

仅依赖 Python 3.11 标准库（含纯 Python RSASSA-PKCS1-v1_5 验签与 SQLite），
不需要外部服务。

## 模块结构

| 模块 | 职责 |
| --- | --- |
| `contracts.py` | 现场事件信封与场景加载（不读系统时间） |
| `crypto.py` | RSA 公钥（PEM/JWK）、RS256 验签、摘要、测试用密钥生成 |
| `domain.py` | 门槛、指标（召回/误剔除/p95 时延）、状态机、回执校验、组合指纹 |
| `store.py` | SQLite 持久化：IMMEDIATE 事务、半开区间历史、幂等回执、封存 |
| `service.py` | 放行编排：验签登记、审批分权、阶段推进、回执归属、冻结回滚、发放 |
| `projector.py` | 把工厂事件流幂等投影到平台（按 received_at 处理，可重放） |
| `replay.py` | 事故取证：受影响产品、工位生效区间、回滚样本证据、封存补数 |
| `scenario.py` | 随附换线事故场景构建器（私钥只存在于构建进程） |
| `cli.py` | `build-incident` / `replay` / `status` 命令 |

## 关键规则如何落地

- **不可拆分的发布组合**：`bundles` + `bundle_calibs` 把模型、配方和
  每工位标定一次性绑定，组合总指纹覆盖全部构件摘要，缺一不发放。
- **只发签名模型**：模型登记必须通过工厂公钥验签；`serving_grant`
  出库前再次验签。影子阶段候选模型**绝不发给机械臂**，现场继续领在役组合。
- **职责分离**：发布创建人不能审批；审批人不能执行/现场确认。
- **三段放行**：影子（需有比对样本）→ 限量（受 `canary_cap` 约束）→
  三工位全部现场确认且门槛通过才扩围；任一工位不达标则整批发冻结。
- **持续安全监控**：限量与扩围阶段每接入一份回执都立即评估三项指标，
  样本不足不判越界，但越界不等待凑样本——随即冻结扩围，未确认工位
  经一个零时长 ROLLED_BACK 区间退回上一稳定组合，等待现场重新确认。
- **迟到回执归实际组合**：按 `occurred_at` 落在工位历史区间归属；
  断网窗口内的迟到回执仍计入实际执行过的组合，回滚生效后冒名候选
  组合的回执拒绝归属。
- **重复回执只计一次**：`receipt_id` 主键天然幂等。
- **封存统计冻结**：批次封存后到达的回执只进 `batch_supplements`
  补充台账，封存快照永不改写。
- **重启安全**：所有状态变更单事务提交；阶段历史是互不重叠的半开区间，
  一座工位任一时刻至多一个生效区间，不会同时属于两个发布阶段。

## 本地校验

    python -m unittest discover -s tests -v
    python -m compileall -q src

## 重放随附换线事故

    PYTHONPATH=src python -m arm_release.cli build-incident \
        --out fixtures/incident_line_change.json
    PYTHONPATH=src python -m arm_release.cli replay \
        fixtures/incident_line_change.json            # 文本取证报告
    PYTHONPATH=src python -m arm_release.cli replay \
        fixtures/incident_line_change.json --json     # 机器可读报告

使用文件数据库可验证重启后状态一致：

    PYTHONPATH=src python -m arm_release.cli replay \
        fixtures/incident_line_change.json --db data/line.db
    PYTHONPATH=src python -m arm_release.cli status --db data/line.db

事故场景（2026-09-10，产品 housing-a17，三工位）复现的内容：

1. v7 稳定组合在役，上午两个批次生产并先后封存；
2. v8 候选组合经不同人员创建/审批后进入影子比对（候选不外发）；
3. 三工位切限量，01/02 现场确认、03 未确认；
4. 换线约两小时后 03 的迟到回执显示误剔除率 18.2%（门槛 2%）→
   冻结整批，03 退回 v7；重复回执只计一次；
5. 封存批次 B 的迟到补数只登记、不改封存统计；
6. 回滚后仍声称 v8 的回执被拒绝并进入死信，作为证据保留。

## 事件接入约定

`EventEnvelope`（event_id/kind/occurred_at/received_at/attributes）由
`projector.py` 按 `received_at` 顺序处理；支持的 kind 见各 `_on_*` 方法
（`signing_key_registered`、`model_registered`、`calibration_registered`、
`recipe_registered`、`bundle_registered`、`stable_provisioned`、
`release_created/approved`、`shadow_started/observed`、`canary_started`、
`station_acknowledged`、`inference_reported`、`batch_sealed`、
`restored_confirmed`）。未识别或无法满足领域规则的事件隔离到
`projection_dead_letter`，不静默丢弃。

持久化文件、临时缓存与本地配置不进入版本库。
