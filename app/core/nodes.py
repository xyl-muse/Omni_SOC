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
    [分析研判节点]：判断事件真实性，区分误报与真实威胁
    目标: 确定是否需要进入深度溯源阶段
    """
    print("\n[Node: Triage] 正在分析事件真实性...")

    # 1. 从标准化的告警 JSON 中提取所需字段
    raw_alert = state.get("raw_alert", {})

    # 拆解出 prompt 需要的各个占位符
    data_source = raw_alert.get("devSourceName", "未知数据源")
    risk_tags = raw_alert.get("riskTag", [])
    description = raw_alert.get("description", "无描述")
    alert_json = str(raw_alert)

    # 2. 将拆解出的字段填充到 prompt 占位符中
    prompt = TRIAGE_SYSTEM_PROMPT.format(
        data_source=data_source,
        alert_json=alert_json,
        risk_tags=risk_tags,
        description=description
    )

    # 3. 调用 GLM-4 进行研判
    response = llm.invoke(prompt)
    content = response.content

    # 4. 记录思考日志
    new_thought = f"[研判结论] {content}"

    # 5. 决策：判断是否为真实事件
    # 真实事件 → 进入深度溯源，误报 → 直接归档
    is_real_threat = any(keyword in content.lower() for keyword in ["真实", "威胁", "confirm", "threat"])
    action = "hunting" if is_real_threat else "archive"

    return {
        "thought_log": state.get("thought_log", []) + [new_thought],
        "status": "analyzing",
        "next_action": action,
        "risk_score": state.get("risk_score", 0) + (70 if is_real_threat else 10)
    }

def hunting_node(state: OmniState) -> Dict:
    """
    [深度溯源节点]：关联相关告警和多维信息，呈现完整事件链路
    目标: 构建完整的事件证据链
    """
    print("[Node: Hunting] 正在进行深度溯源...")

    # 模拟多维度证据收集
    evidences = [
        f"[网络证据] 发现可疑连接: {state.get('raw_alert', {}).get('description', 'N/A')}",
        "[终端证据] 进程树显示异常的父子进程关系",
        "[关联证据] 发现同一时间段内3台主机出现相似告警",
        "[时间证据] 攻击时间跨度: 2小时15分钟"
    ]

    return {
        "evidence_pool": state.get("evidence_pool", []) + evidences,
        "next_action": "response",
        "status": "hunting_completed"
    }

def response_node(state: OmniState) -> Dict:
    """
    [自动处置节点]：根据事件信息和端侧处置能力，完成自动化处置
    支持模式: 自动处置 / 人工审核 / 混合模式
    """
    print("[Node: Response] 正在执行自动处置...")

    # 获取处置模式配置 (默认为混合模式)
    response_mode = state.get("response_mode", "hybrid")  # auto/manual/hybrid
    risk_score = state.get("risk_score", 0)

    # 根据风险等级和处置模式决定是否需要人工审核
    needs_approval = False

    if response_mode == "manual":
        needs_approval = True
    elif response_mode == "hybrid" and risk_score < 80:
        needs_approval = True

    # 生成处置建议
    if needs_approval:
        action = "pending_approval"
        report = f"处置建议: 高风险事件需要人工审核。风险评分: {risk_score}"
        print(f"[待审核] {report}")
    else:
        action = "execute"
        report = f"自动执行: 主机隔离 + IP封禁 + 文件清理。风险评分: {risk_score}"
        print(f"[自动执行] {report}")

    return {
        "final_report": report,
        "next_action": "archive",
        "status": "response_completed",
        "needs_approval": needs_approval
    }

def archive_node(state: OmniState) -> Dict:
    """
    [数据归档节点]：将事件管理全生命周期以规范格式完成归档
    目标: 写入AI表格，支持后续分析和审计
    """
    print("[Node: Archive] 正在归档事件数据...")

    # 构建归档数据结构
    archive_data = {
        "event_id": f"OMNI-{hash(str(state.get('raw_alert', {})))}",
        "timestamp": "2026-03-14",
        "raw_alert": state.get("raw_alert", {}),
        "triage_result": state.get("thought_log", ["N/A"]),
        "evidence_chain": state.get("evidence_pool", []),
        "response_action": state.get("final_report", "N/A"),
        "status": state.get("status", "unknown"),
        "risk_score": state.get("risk_score", 0)
    }

    # 模拟写入AI表格
    print(f"[归档完成] 事件ID: {archive_data['event_id']}")
    print(f"[归档内容] 原始告警、研判结论、证据链、处置记录已标准化存储")

    return {
        "next_action": "end",
        "status": "archived",
        "archive_id": archive_data["event_id"]
    }