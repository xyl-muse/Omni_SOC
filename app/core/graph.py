# app/core/graph.py
from langgraph.graph import StateGraph, END
from .state import OmniState
from .nodes import triage_node, hunting_node, response_node, archive_node

def route_after_triage(state: OmniState):
    """研判节点后的路由：真实事件→溯源，误报→归档"""
    if state["next_action"] == "hunting":
        return "hunting"
    return "archive"

workflow = StateGraph(OmniState)

# 添加四个核心节点
workflow.add_node("triage", triage_node)      # 分析研判节点
workflow.add_node("hunting", hunting_node)    # 深度溯源节点
workflow.add_node("response", response_node)  # 自动处置节点
workflow.add_node("archive", archive_node)    # 数据归档节点

# 设置逻辑连线
workflow.set_entry_point("triage")

# 研判节点路由：真实事件进入溯源，误报直接归档
workflow.add_conditional_edges(
    "triage",
    route_after_triage,
    {
        "hunting": "hunting",
        "archive": "archive"
    }
)

# 固定连线：溯源→处置→归档→结束
workflow.add_edge("hunting", "response")
workflow.add_edge("response", "archive")
workflow.add_edge("archive", END)

app = workflow.compile()