# Omni_SOC/app/core/state.py
from typing import Annotated, List, Optional, Dict, Any
from typing_extensions import TypedDict
import operator

# 使用 Annotated[List, operator.add] 是 LangGraph 的精髓
# 它允许不同节点生成的证据不断“追加”到列表中，而不会互相覆盖
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
    
    # 研判状态：'investigating' | 'confirmed' | 'false_positive' | 'manual_review'
    status: str
    
    # 下一个动作指令 (由 LLM 决定)
    next_action: Optional[str]
    
    # 最终处置建议
    final_report: Optional[Dict[str, Any]]