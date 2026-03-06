# app/core/nodes.py
import json
from .state import OmniState
from .prompts import TRIAGE_SYSTEM_PROMPT

# 注意：现阶段我们先用“模拟 AI”来调通逻辑，Day 3 再接入真正的 OpenAI API
def triage_node(state: OmniState):
    print("\n[Node: Triage] 正在分析原始告警...")
    alert = state["raw_alert"]
    
    # 这里模拟了 LLM 解析告警的过程
    # 在实际运行中，我们会调用 llm.invoke()
    thought = f"检测到来自 {alert.get('devSourceName')} 的告警，风险标签包含 {alert.get('riskTag')}。"
    
    # 逻辑判断：如果包含“恶意行为”或“病毒”，自动进入 hunting
    action = "hunting" if "病毒" in alert.get("name", "") else "response"
    
    return {
        "thought_log": [thought],
        "risk_score": 85 if action == "hunting" else 20,
        "next_action": action,
        "status": "investigating"
    }

def hunting_node(state: OmniState):
    print(f"[Node: Hunting] AI 决定进行深挖。当前思考: {state['thought_log'][-1]}")
    # 模拟取证动作
    evidence = {"type": "process_check", "content": "发现异常进程：powershell.exe 执行了 base64 指令"}
    return {
        "evidence_pool": [evidence],
        "thought_log": ["在主机上发现了可疑的 PowerShell 进程，确认威胁存在。"]
    }

def response_node(state: OmniState):
    print("[Node: Response] 正在汇总最终报告...")
    return {
        "status": "completed",
        "final_report": {
            "conclusion": "确认感染，建议立即隔离",
            "score": state["risk_score"]
        }
    }