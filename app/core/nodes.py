# app/core/nodes.py
import os
import time
from typing import Dict, List
from dotenv import load_dotenv
from langchain_community.chat_models import ChatZhipuAI
import json
from .state import OmniState
from .prompts import TRIAGE_SYSTEM_PROMPT
from .utils import safe_llm_invoke, log_node_execution, validate_alert_data, logger
from .risk_scoring import risk_engine
from .evidence_correlation import correlation_engine

# 加载环境变量
load_dotenv()

# 初始化大脑：智谱 GLM-4
# 安全研判场景建议将 temperature 调低，保证输出的稳定性
llm = ChatZhipuAI(
    model="glm-4",
    temperature=0.1
)

def build_enhanced_triage_prompt(data_source: str, alert_json: str, risk_tags: List,
                               description: str, risk_analysis: Dict) -> str:
    """
    构建增强的研判prompt，包含风险评分分析结果

    Args:
        data_source: 数据源名称
        alert_json: 原始告警JSON
        risk_tags: 风险标签列表
        description: 事件描述
        risk_analysis: 风险评分分析结果

    Returns:
        增强的prompt字符串
    """
    # 构建风险评分分析描述
    risk_analysis_desc = f"""
【风险评分分析】
- 数据源评分: {risk_analysis['source_score']:.1f}
- 标签评分: {risk_analysis['tag_score']:.1f}
- 描述评分: {risk_analysis['description_score']:.1f}
- 误报风险: {risk_analysis['false_positive_risk']:.2f}
- 综合评分: {risk_analysis['final_score']:.1f}
- 置信度: {risk_analysis['confidence']:.2f}
"""

    # 构建增强的prompt
    enhanced_prompt = f"""你是一个顶尖的自主 AI-SOC 分析研判专家。你正在处理一起由 {data_source} 触发的安全事件。

{risk_analysis_desc}

【原始告警 JSON】
{alert_json}

【风险标签】
{risk_tags}

【事件描述】
{description}

【你的任务】
1. 参考风险评分分析，结合你的专业知识进行研判
2. 判断事件真实性：基于风险标签、事件描述和评分分析，判断这是否是一起真实的安全事件
3. 决策路径：
   - 如果综合评分>=70且置信度>=0.6，请判断为真实事件，说明"真实威胁"
   - 如果综合评分<=40或误报风险>=0.7，请判断为误报，说明"误报"
   - 中间情况需要你结合其他因素做出判断

【特别提醒】
- 误报风险高于0.7时，倾向于判断为误报
- 置信度低于0.4时，说明不确定性高，需要更谨慎判断
- 高危标签（恶意软件、勒索软件等）即使描述评分较低，也要优先考虑真实威胁

【输出要求】
必须只输出 JSON 格式，严禁包含任何其他文字：
{{
    "thought": "基于风险评分分析和具体事件内容的综合分析逻辑...",
    "is_real_threat": true/false,
    "risk_score_adjustment": "建议调整风险评分: 保持原评分/适当调整(具体分数)",
    "next_action": "hunting"(真实事件) 或 "archive"(误报),
    "reason": "选择该路径的核心理由"
}}
"""
    return enhanced_prompt

def build_thought_log(risk_analysis: Dict, llm_response: str) -> str:
    """
    构建详细的思考日志

    Args:
        risk_analysis: 风险评分分析结果
        llm_response: LLM响应内容

    Returns:
        格式化的思考日志字符串
    """
    thought_log = f"""
[研判分析]
- 数据源评分: {risk_analysis['source_score']:.1f}
- 标签评分: {risk_analysis['tag_score']:.1f}
- 描述评分: {risk_analysis['description_score']:.1f}
- 误报风险: {risk_analysis['false_positive_risk']:.2f}
- 综合评分: {risk_analysis['final_score']:.1f}
- 置信度: {risk_analysis['confidence']:.2f}

[LLM研判结论]
{llm_response}
"""
    return thought_log.strip()

def make_triage_decision(risk_analysis: Dict, llm_response: str) -> Dict:
    """
    综合风险评分和LLM分析做出最终决策

    Args:
        risk_analysis: 风险评分分析结果
        llm_response: LLM响应内容

    Returns:
        决策结果字典
    """
    final_risk_score = risk_analysis['final_score']

    # 1. 从LLM响应中提取决策倾向
    llm_real_threat = any(keyword in llm_response.lower() for keyword in
                        ["真实威胁", "真实", "threat", "confirm", "true"])

    # 2. 综合决策逻辑
    is_real_threat = False
    action = "archive"

    # 优先规则：误报风险极高
    if risk_analysis['false_positive_risk'] >= 0.7:
        is_real_threat = False
        action = "archive"
        logger.info("决策: 误报风险极高，判断为误报")

    # 规则2：综合评分极高且置信度不错
    elif final_risk_score >= 80 and risk_analysis['confidence'] >= 0.5:
        is_real_threat = True
        action = "hunting"
        logger.info(f"决策: 综合评分{final_risk_score:.1f}极高，判断为真实威胁")

    # 规则3：综合评分很低或误报风险较高
    elif final_risk_score <= 40 or risk_analysis['false_positive_risk'] >= 0.5:
        is_real_threat = False
        action = "archive"
        logger.info(f"决策: 综合评分{final_risk_score:.1f}较低或误报风险较高，判断为误报")

    # 规则4：中等评分，参考LLM决策
    else:
        if risk_analysis['confidence'] >= 0.5:
            # 置信度不错时，优先参考LLM决策
            is_real_threat = llm_real_threat
            action = "hunting" if is_real_threat else "archive"
            logger.info(f"决策: 综合评分{final_risk_score:.1f}中等，参考LLM决策({llm_real_threat})")
        else:
            # 置信度不高时，保守决策
            is_real_threat = final_risk_score >= 60
            action = "hunting" if is_real_threat else "archive"
            logger.info(f"决策: 置信度较低，保守决策基于综合评分({final_risk_score:.1f})")

    return {
        'is_real_threat': is_real_threat,
        'action': action,
        'final_risk_score': final_risk_score,
        'llm_real_threat': llm_real_threat
    }

def build_hunting_thought_log(correlation_result: Dict) -> str:
    """
    构建深度溯源的思考日志

    Args:
        correlation_result: 证据关联分析结果

    Returns:
        格式化的思考日志字符串
    """
    thought_log = f"""
[深度溯源分析]
- 网络证据: {len(correlation_result['network_evidence'])}条
- 终端证据: {len(correlation_result['endpoint_evidence'])}条
- 关联证据: {len(correlation_result['correlation_evidence'])}条
- 总证据数: {correlation_result['total_evidence_count']}条
- 高置信度证据: {correlation_result['high_confidence_count']}条
- 整体置信度: {correlation_result['evidence_confidence']:.2f}

[攻击链分析]
MITRE ATT&CK战术: {len(correlation_result['attack_chain'])}个阶段
"""
    return thought_log.strip()

def build_attack_chain_summary(attack_chain: List[Dict]) -> str:
    """
    构建攻击链摘要

    Args:
        attack_chain: MITRE ATT&CK攻击链

    Returns:
        攻击链摘要字符串
    """
    if not attack_chain:
        return "攻击链: 未检测到明确的攻击阶段"

    chain_steps = []
    for step in attack_chain:
        tactic = step.get('tactic', '')
        technique = step.get('technique', '')
        chain_steps.append(f"{tactic} → {technique}")

    return f"攻击链: {' → '.join(chain_steps)}"

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

        # 1. 使用多维度风险评分引擎计算基础评分
        risk_analysis = risk_engine.calculate_risk_score(raw_alert)

        # 2. 从标准化的告警 JSON 中提取所需字段
        data_source = raw_alert.get("devSourceName", "未知数据源")
        risk_tags = raw_alert.get("riskTag", [])
        description = raw_alert.get("description", "无描述")
        alert_json = str(raw_alert)

        # 3. 构建增强的prompt，包含风险评分分析结果
        enhanced_prompt = build_enhanced_triage_prompt(
            data_source, alert_json, risk_tags, description, risk_analysis
        )

        # 4. 使用安全的LLM调用（带重试机制）
        content = safe_llm_invoke(llm, enhanced_prompt)

        # 5. 记录详细的思考日志
        new_thought = build_thought_log(risk_analysis, content)

        # 6. 综合决策：结合风险评分和LLM分析
        decision = make_triage_decision(risk_analysis, content)

        logger.info(f"研判结果: {'真实威胁' if decision['is_real_threat'] else '误报'}, "
                   f"风险评分: {decision['final_risk_score']:.1f}, 置信度: {risk_analysis['confidence']:.2f}")

        return {
            "thought_log": state.get("thought_log", []) + [new_thought],
            "status": "analyzing",
            "next_action": decision['action'],
            "risk_score": decision['final_risk_score'],
            "confidence": risk_analysis['confidence']
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
        # 获取原始告警数据
        raw_alert = state.get("raw_alert", {})

        # 获取已有证据
        existing_evidence = state.get("evidence_pool", [])

        # 使用证据关联引擎进行深度溯源分析
        correlation_result = correlation_engine.correlate_evidence(raw_alert, existing_evidence)

        # 构建详细的思考日志
        hunting_thought = build_hunting_thought_log(correlation_result)

        # 合并新证据到证据池
        new_evidences = correlation_result['standardized_evidences']
        updated_evidence_pool = existing_evidence + new_evidences

        # 附加攻击链信息
        attack_chain_info = build_attack_chain_summary(correlation_result['attack_chain'])

        logger.info(f"深度溯源完成: 总证据{correlation_result['total_evidence_count']}条, "
                   f"高置信度{correlation_result['high_confidence_count']}条, "
                   f"整体置信度{correlation_result['evidence_confidence']:.2f}")

        return {
            "evidence_pool": updated_evidence_pool,
            "next_action": "response",
            "status": "hunting_completed",
            "attack_chain": correlation_result['attack_chain'],
            "evidence_confidence": correlation_result['evidence_confidence'],
            "timeline_analysis": correlation_result['timeline_analysis']
        }

    except Exception as e:
        logger.error(f"溯源节点执行异常: {e}")
        return {
            "evidence_pool": state.get("evidence_pool", []) + [f"[错误] 溯源失败: {e}"],
            "next_action": "response",
            "status": "hunting_error",
            "attack_chain": [],
            "evidence_confidence": 0.0,
            "timeline_analysis": {}
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