# 机械臂视觉模型换线放行

机械臂工位以发布组合绑定视觉模型、相机标定和产品配方。仓库中的协议与换线回执样例用于复现组合生效及推理结果归属。

## 资料约定

- fixtures/incident.json 保存一组可公开的事故事件，时间均带 UTC 偏移。
- src/arm_release/contracts.py 定义最小事件信封与严格校验入口。
- 未识别的业务字段保留在 attributes 中，接入方不得静默丢弃。
- event_id 标识现场事实，occurred_at 与 received_at 分别表示发生和接收时间。

## 本地校验

项目要求 Python 3.11 或更高版本，不依赖外部服务。运行下列命令可检查协议样例和源码：

    python -m unittest discover -s tests -v
    python -m compileall -q src

领域逻辑应放在独立模块中，协议解析不得隐式读取系统时间。持久化文件、临时缓存与本地配置不进入版本库。