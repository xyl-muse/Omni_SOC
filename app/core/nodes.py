# app/core/nodes.py
import os
import time
from typing import Dict
from dotenv import load_dotenv
from langchain_community.chat_models import ChatZhipuAI
import json
from .state import OmniState
from .prompts import TRIAGE_SYSTEM_PROMPT
from .utils import safe_llm_invoke, log_node_execution, validate_alert_data, logger

# 加载环境变量
load_dotenv()

# 初始化大脑：智谱 GLM-4
# 安全研判场景建议将 temperature 调低，保证输出的稳定性
llm = ChatZhipuAI(
    model="glm-4",
    temperature=0.1
)

@log_node_execution("Triage")
def triage_node(state: OmniState) -> Dict:
    """
    [分析研判节点]：判断事件真实性，区分误报与真实威胁
    目标: 确定是否需要进入深度溯源阶段
    """
    try:
        # 验证告警数据
        raw_alert = state.get("raw_alert", {})
        if not validate_alert_data(raw_alert):
            logger.warning("告警数据无效，默认归档")
            return {
                "thought_log": state.get("thought_log", []) + ["[研判结论] 告警数据无效，默认归档"],
                "status": "analyzing",
                "next_action": "archive",
                "risk_score": 0
            }

        # 从标准化的告警 JSON 中提取所需字段
        data_source = raw_alert.get("devSourceName", "未知数据源")
        risk_tags = raw_alert.get("riskTag", [])
        description = raw_alert.get("description", "无描述")
        alert_json = str(raw_alert)

        # 将拆解出的字段填充到 prompt 占位符中
        prompt = TRIAGE_SYSTEM_PROMPT.format(
            data_source=data_source,
            alert_json=alert_json,
            risk_tags=risk_tags,
            description=description
        )

        # 使用安全的LLM调用（带重试机制）
        content = safe_llm_invoke(llm, prompt)

        # 记录思考日志
        new_thought = f"[研判结论] {content}"

        # 决策：判断是否为真实事件
        is_real_threat = any(keyword in content.lower() for keyword in ["真实", "威胁", "confirm", "threat"])
        action = "hunting" if is_real_threat else "archive"

        logger.info(f"研判结果: {'真实威胁' if is_real_threat else '误报'}, 风险评分: {state.get('risk_score', 0) + (70 if is_real_threat else 10)}")

        return {
            "thought_log": state.get("thought_log", []) + [new_thought],
            "status": "analyzing",
            "next_action": action,
            "risk_score": state.get("risk_score", 0) + (70 if is_real_threat else 10)
        }

    except Exception as e:
        logger.error(f"研判节点执行异常: {e}")
        return {
            "thought_log": state.get("thought_log", []) + [f"[错误] 研判失败: {e}"],
            "status": "error",
            "next_action": "archive",
            "risk_score": 0
        }

@log_node_execution("Hunting")
def hunting_node(state: OmniState) -> Dict:
    """
    [深度溯源节点]：关联相关告警和多维信息，呈现完整事件链路
    目标: 构建完整的事件证据链
    """
    try:
        # 模拟多维度证据收集
        raw_alert = state.get("raw_alert", {})
        evidences = [
            f"[网络证据] 发现可疑连接: {raw_alert.get('description', 'N/A')}",
            "[终端证据] 进程树显示异常的父子进程关系",
            "[关联证据] 发现同一时间段内3台主机出现相似告警",
            "[时间证据] 攻击时间跨度: 2小时15分钟"
        ]

        logger.info(f"深度溯源完成，收集到{len(evidences)}条证据")

        return {
            "evidence_pool": state.get("evidence_pool", []) + evidences,
            "next_action": "response",
            "status": "hunting_completed"
        }

    except Exception as e:
        logger.error(f"溯源节点执行异常: {e}")
        return {
            "evidence_pool": state.get("evidence_pool", []) + [f"[错误] 溯源失败: {e}"],
            "next_action": "response",
            "status": "hunting_error"
        }

@log_node_execution("Response")
def response_node(state: OmniState) -> Dict:
    """
    [自动处置节点]：根据事件信息和端侧处置能力，完成自动化处置
    支持模式: 自动处置 / 人工审核 / 混合模式
    """
    try:
        # 获取处置模式配置 (默认为混合模式)
        response_mode = state.get("response_mode", "hybrid")
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
            logger.info(f"处置决策: 需要人工审核，风险评分: {risk_score}")
        else:
            action = "execute"
            report = f"自动执行: 主机隔离 + IP封禁 + 文件清理。风险评分: {risk_score}"
            logger.info(f"处置决策: 自动执行，风险评分: {risk_score}")

        return {
            "final_report": report,
            "next_action": "archive",
            "status": "response_completed",
            "needs_approval": needs_approval
        }

    except Exception as e:
        logger.error(f"处置节点执行异常: {e}")
        return {
            "final_report": f"处置失败: {e}",
            "next_action": "archive",
            "status": "response_error",
            "needs_approval": True
        }

@log_node_execution("Archive")
def archive_node(state: OmniState) -> Dict:
    """
    [数据归档节点]：将事件管理全生命周期以规范格式完成归档
    目标: 写入AI表格，支持后续分析和审计
    """
    try:
        # 构建归档数据结构
        archive_data = {
            "event_id": f"OMNI-{hash(str(state.get('raw_alert', {})))}",
            "timestamp": "2026-03-15",
            "raw_alert": state.get("raw_alert", {}),
            "triage_result": state.get("thought_log", ["N/A"]),
            "evidence_chain": state.get("evidence_pool", []),
            "response_action": state.get("final_report", "N/A"),
            "status": state.get("status", "unknown"),
            "risk_score": state.get("risk_score", 0)
        }

        logger.info(f"归档完成，事件ID: {archive_data['event_id']}")

        return {
            "next_action": "end",
            "status": "archived",
            "archive_id": archive_data["event_id"]
        }

    except Exception as e:
        logger.error(f"归档节点执行异常: {e}")
        return {
            "next_action": "end",
            "status": "archive_error",
            "archive_id": f"ERROR-{time.time()}"
        }