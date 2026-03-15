# Omni_SOC/app/core/state.py
from typing import Annotated, List, Optional, Dict, Any
from typing_extensions import TypedDict
import operator

# 使用 Annotated[List, operator.add] 是 LangGraph 的精髓
# 它允许不同节点生成的证据不断”追加”到列表中，而不会互相覆盖
class OmniState(TypedDict):
    # 原始告警信息 (Input)
    raw_alert: Dict[str, Any]

    # 调查过程中收集到的证据池
    # 比如：[{'type': 'process_list', 'data': [...]}, {'type': 'pcap_analysis', 'data': 'malicious'}]
    evidence_pool: Annotated[List[Dict[str, Any]], operator.add]

    # AI 的思考链条 (Thought Track)
    thought_log: Annotated[List[str], operator.add]

    # 动态风险评分 (0-100)
    risk_score: int

    # 处理状态：'start' | 'analyzing' | 'hunting_completed' | 'response_completed' | 'archived'
    status: str

    # 下一个动作指令 (由 LLM 决定)
    next_action: Optional[str]

    # 最终处置报告
    final_report: Optional[str]

    # 处置模式：'auto'(自动处置) | 'manual'(人工审核) | 'hybrid'(混合模式)
    response_mode: Optional[str]

    # 是否需要人工审批
    needs_approval: Optional[bool]

    # 归档事件ID
    archive_id: Optional[str]