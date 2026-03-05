# app/core/graph.py
from langgraph.graph import StateGraph, END
from .state import OmniState
from .nodes import triage_node, hunting_node, response_node

def should_continue(state: OmniState):
    """条件路由逻辑"""
    if state["next_action"] == "hunting":
        return "hunting"
    return "response"

workflow = StateGraph(OmniState)

# 添加节点
workflow.add_node("triage", triage_node)
workflow.add_node("hunting", hunting_node)
workflow.add_node("response", response_node)

# 设置逻辑连线
workflow.set_entry_point("triage")

# 使用条件边：triage 执行完后，根据 next_action 决定去向
workflow.add_conditional_edges(
    "triage",
    should_continue,
    {
        "hunting": "hunting",
        "response": "response"
    }
)

workflow.add_edge("hunting", "response")
workflow.add_edge("response", END)

app = workflow.compile()