# 机械臂视觉模型换线放行平台

新品换线后误剔除率升高、各工位执行的模型版本无法追溯——本平台把**视觉模型、相机标定、
产品配方**绑成不可拆开的发布组合，强制走「影子比对 → 限量试运行 → 扩围 → 全量确认」流程，
任一安全指标越界即冻结扩围，并把尚未确认的工位退回上一稳定组合。全部逻辑仅依赖
Python 3.11 标准库（含一份按 RFC 8032 实现并与 OpenSSL 交叉验证过的 Ed25519）。

## 核心规则

1. **发布组合不可拆开**：`bundle = 模型(签名) + 标定快照 + 配方版本`，组合清单由
   release 角色密钥整体签名；引用未登记部件或签名不符一律拒绝。
2. **未签名模型到不了机械臂**：模型经 model 角色密钥验签后才能登记；`serving` 下发视图
   在读取路径上再次复核模型签名与组合签名。
3. **先影子后限量**：候选先在 `shadow` 只记录不驱动机械臂（需与在役模型配对比对），
   门槛通过才进 `canary`、`rollout`，最后 `active` 成为新稳定组合。
4. **配方门槛**：每个产品配方规定缺陷召回下限、误剔除率上限、P95 推理时延上限；
   阶段窗口样本量达标后三项全部在界内才放行（窗口内零缺陷时召回率不可评估，判不通过）。
5. **职责分离**：组合审批人不能是阶段执行人。
6. **迟到回执归实际执行组合**：回执按 `occurred_at` 用阶段时间线归位，断网重连后补送
   仍计入当时在役的组合/阶段；`receipt_id` 去重，重传只计一次；发生时刻不在任何执行
   区间的回执隔离（quarantine）留证，不污染统计。
7. **越界即冻结回滚**：限量试运行/扩围窗口内指标越界，立即冻结该组合，所有仍有候选
   流水线（未确认）的工位回退到上一稳定组合；已确认全量的工位不受影响。
8. **封存统计不可变**：批次封存生成逐工位统计快照；封存后的补数一律隔离，
   `batch-summary` 永远返回封存那一刻的数字。
9. **重启安全**：状态迁移与写入在单条 SQLite 事务（BEGIN IMMEDIATE）内完成；
   每座工位至多一条候选流水线，重启后不会同时属于两个阶段。
10. **不隐式读时钟**：协议解析不带系统时间；服务时钟可注入，事故可确定性重放。

## 模块

| 模块 | 职责 |
| --- | --- |
| `contracts.py` | 现场事件信封与场景文件校验（既有） |
| `crypto.py` | RFC 8032 Ed25519 签名/验签、SHA-256 摘要、规范 JSON 编码 |
| `models.py` | 配方门槛、模型、标定、发布组合等领域类型 |
| `stats.py` | 窗口指标累计、P95、门槛判定 |
| `store.py` | SQLite schema、事务与各表读写 |
| `platform.py` | 注册验签、阶段推进、回执归属、冻结回滚、批次封存、下发视图 |
| `replay.py` | 事件流重放：受影响产品、各工位生效区间、回滚证据 |
| `demo_incident.py` | `line-change-a17` 换线事故的确定性复现脚本 |

## 本地校验

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q src
```

## 复现随附的换线事故

```bash
PYTHONPATH=src python3 -m arm_release --db data/demo.sqlite3 demo
PYTHONPATH=src python3 -m arm_release --db data/demo.sqlite3 replay
```

事故时间线（UTC+8，2026-09-10）：

- `08:00` 三座工位（arm-cell-01/02/03）在役稳定组合 **B0**（旧模型+旧标定，housing-a17 v3）
- `09:00` 候选组合 **B1**（新模型+新标定）进入影子比对；`09:20` 限量试运行；`10:00` 扩围
- `11:00` 封存早班批次 `L42-morning`
- `11:30` 扩围中途服务重启（`--no-restart` 可关闭），状态与下发视图不变
- `11:55` arm-cell-03 断网，回执滞留现场
- `12:05` arm-cell-03 良品被误剔除（误剔除率 0.125 > 0.02），**触发冻结**，
  三座未确认工位全部回退 B0
- `12:20` 网络恢复：迟到回执归入 B1 扩围窗口；重传回执只计一次；回滚后产生的
  B1 回执被隔离
- `12:25` 已封存批次的补数被隔离，封存统计保持 36 条回执不变

重放报告直接给出：`affected_products`（housing-a17 v3）、每工位各阶段
`[start, end)` 生效区间、`rollbacks`（时间、退回组合、越界指标与指标值）、
`evidence_samples`（触发样本 `r-arm-cell-03-trigger` 及其波及的三座工位）。

## CLI 工作流

```bash
# 1) 信任根：导入工厂 model / release 公钥
python3 -m arm_release keygen --kid k-model --out model.key.json --public-out model.pub.json
python3 -m arm_release add-key model.pub.json --role model

# 2) 登记已签名模型、标定快照、配方门槛
python3 -m arm_release register-model model.env.json
python3 -m arm_release register-calibration cal.env.json
python3 -m arm_release register-recipe recipe.env.json

# 3) 登记并审批发布组合（审批人与执行人必须不同）
python3 -m arm_release register-bundle bundle.env.json
python3 -m arm_release approve B1 --by qa-lead.chen

# 4) 初始稳定组合，然后按工位放行
python3 -m arm_release stable arm-cell-03 B0
python3 -m arm_release shadow arm-cell-03 B1 --executor ops-eng.li
python3 -m arm_release promote arm-cell-03 B1 --executor ops-eng.li   # -> canary
python3 -m arm_release promote arm-cell-03 B1 --executor ops-eng.li   # -> rollout
python3 -m arm_release promote arm-cell-03 B1 --executor ops-eng.li   # -> active

# 5) 回执接入（可迟到、可重传）
python3 -m arm_release receipt r001.env.json

# 6) 冻结/回滚、批次封存、下发视图、事故重放
python3 -m arm_release freeze B1 --by qa-lead.chen
python3 -m arm_release seal L42-morning
python3 -m arm_release batch-summary L42-morning
python3 -m arm_release serving arm-cell-03
python3 -m arm_release replay
```

## 信封格式

模型（model 密钥对 `payload` 签名）：

```json
{
  "model_id": "housing-vision", "version": "2026.09.10",
  "digest": "sha256:…", "kid": "k-factory-model-2026",
  "signature": "<base64 Ed25519 over canonical(payload)>",
  "payload": {"model_id": "…", "version": "…", "digest": "sha256:…"}
}
```

发布组合（release 密钥对三要素清单签名）：`parts.manifest` 为
`{bundle_id, recipe, recipe_version, model{model_id,version,digest},
calibration{snapshot_id,camera_id,digest}}`，签名覆盖该清单。

回执：`{receipt_id, station_id, bundle_id, occurred_at, received_at,
truth(good|defect), decision(accept|reject), latency_ms,
champion_decision?, batch_id?}`，所有时间必须带时区偏移。

持久化文件（`data/`、`*.sqlite3*`）、密钥与缓存不进入版本库。
