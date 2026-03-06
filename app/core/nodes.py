# app/core/nodes.py
import os
from typing import Dict, List
from dotenv import load_dotenv
from langchain_community.chat_models import ChatZhipuAI
import json
from .state import OmniState
from .prompts import TRIAGE_SYSTEM_PROMPT

# 加载环境变量
load_dotenv()

# 初始化大脑：智谱 GLM-4
# 安全研判场景建议将 temperature 调低，保证输出的稳定性
llm = ChatZhipuAI(
    model="glm-4", 
    temperature=0.1
)

def triage_node(state: OmniState) -> Dict:
    """
    [研判专家]：负责初步分析告警并决定下一步动作
    """
    print("\n[Node: Triage] 专家正在研判中...")
    
    # 1. 准备输入：将原始告警转化为字符串喂给 AI
    alert_info = str(state.get("raw_alert", {}))
    prompt = TRIAGE_SYSTEM_PROMPT.format(alert_json=alert_info)
    
    # 2. 调用 GLM-4 进行研判
    # 在后续版本中，我们会通过 llm.bind_tools() 绑定 skills
    response = llm.invoke(prompt)
    content = response.content
    
    # 3. 记录思考日志
    new_thought = f"研判结论: {content}"
    
    # 4. 关键：解析 AI 的意图（此处假设 AI 返回了结构化建议）
    # 如果 AI 认为有威胁且需要查 IP/进程，则设置 next_action 为 "hunting"
    # 暂时通过简单的关键词模拟逻辑，后续将升级为 JsonOutputParser
    action = "hunting" if "hunting" in content.lower() else "response"
    
    return {
        "thought_log": state.get("thought_log", []) + [new_thought],
        "status": "analyzing",
        "next_action": action
    }

def hunting_node(state: OmniState) -> Dict:
    """
    [溯源专家]：负责深度挖掘证据（后续将集成 skills 执行具体的取证命令）
    """
    print("[Node: Hunting] 专家正在溯源取证...")
    # 模拟溯源动作
    evidence = "发现可疑进程：powershell.exe 执行了 base64 加密脚本"
    return {
        "evidence_pool": state.get("evidence_pool", []) + [evidence],
        "next_action": "response"
    }

def response_node(state: OmniState) -> Dict:
    """
    [处置专家]：汇总所有信息，给出最终建议
    """
    print("[Node: Response] 正在生成最终处置建议报告...")
    report = "建议立即隔离主机并封禁源 IP。"
    return {
        "final_report": report,
        "next_action": "end"
    }