"""机械臂视觉模型换线放行的领域协议。"""

from .contracts import ContractError, EventEnvelope, load_events

__all__ = ["ContractError", "EventEnvelope", "load_events"]