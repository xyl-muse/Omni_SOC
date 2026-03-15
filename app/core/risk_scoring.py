# app/core/risk_scoring.py - 多维度风险评分算法
from typing import Dict, List
from .utils import logger

class RiskScoringEngine:
    """多维度风险评分引擎"""

    def __init__(self):
        # 数据源权重配置
        self.data_source_weights = {
            'EDR': 1.5,        # 终点检测响应 - 高可信度
            'SIEM': 1.2,       # 安全信息事件管理 - 较高可信度
            'IDS': 1.3,         # 入侵检测系统 - 较高可信度
            'Firewall': 1.1,    # 防火墙 - 中等可信度
            'WAF': 1.1,         # Web应用防火墙 - 中等可信度
            'default': 1.0       # 默认权重
        }

        # 风险标签评分配置
        self.risk_tag_scores = {
            # 高危标签 (70-90分)
            '恶意软件': 85,
            '勒索软件': 90,
            '木马': 85,
            '后门': 88,
            '远程执行': 85,
            '提权': 80,
            '权限提升': 80,

            # 中危标签 (50-70分)
            '异常行为': 60,
            '可疑连接': 65,
            '数据泄露': 75,
            '内部威胁': 70,
            '横向移动': 65,

            # 低危标签 (20-50分)
            '配置错误': 30,
            '弱密码': 25,
            '扫描探测': 35,
            '网络异常': 40,
            '系统异常': 35,

            # 默认标签
            'default': 40
        }

        # 误报特征库
        self.false_positive_patterns = [
            # 系统维护相关
            r'系统维护|system maintenance|例行检查',
            r'管理员操作|admin operation|维护窗口',

            # 正常业务相关
            r'正常业务|normal business|日常操作',
            r'定期备份|scheduled backup|自动更新',

            # 测试相关
            r'测试环境|test environment|开发环境',
            r'渗透测试|penetration test|安全扫描',

            # 已知误报模式
            r'误报|false positive|已知异常',
            r'白名单|whitelist|信任源'
        ]

    def calculate_risk_score(self, raw_alert: Dict) -> Dict:
        """
        计算多维度风险评分

        Args:
            raw_alert: 原始告警数据

        Returns:
            包含评分详情的字典
        """
        try:
            data_source = raw_alert.get('devSourceName', 'default')
            risk_tags = raw_alert.get('riskTag', [])
            description = raw_alert.get('description', '')

            # 1. 数据源评分
            source_weight = self.data_source_weights.get(data_source, self.data_source_weights['default'])
            source_score = 50 * source_weight  # 基础分50 * 权重

            # 2. 风险标签评分
            tag_scores = []
            for tag in risk_tags:
                tag_score = self.risk_tag_scores.get(tag, self.risk_tag_scores['default'])
                tag_scores.append(tag_score * source_weight)  # 标签分也受数据源权重影响

            tag_score = max(tag_scores) if tag_scores else 40 * source_weight

            # 3. 描述分析评分
            description_score = self._analyze_description(description, source_weight)

            # 4. 误报检测
            false_positive_risk = self._detect_false_positive(description, risk_tags)

            # 5. 综合评分 (加权平均)
            final_score = self._calculate_final_score(
                source_score, tag_score, description_score, false_positive_risk
            )

            # 6. 置信度评估
            confidence = self._calculate_confidence(
                source_score, tag_score, description_score, false_positive_risk
            )

            result = {
                'final_score': final_score,
                'confidence': confidence,
                'source_score': source_score,
                'tag_score': tag_score,
                'description_score': description_score,
                'false_positive_risk': false_positive_risk,
                'is_high_risk': final_score >= 70,
                'is_low_risk': final_score <= 30
            }

            logger.info(f"风险评分计算完成: 最终得分{final_score:.1f}, 置信度{confidence:.1f}")
            return result

        except Exception as e:
            logger.error(f"风险评分计算异常: {e}")
            return {
                'final_score': 50,
                'confidence': 0.5,
                'source_score': 50,
                'tag_score': 50,
                'description_score': 50,
                'false_positive_risk': 0.5,
                'is_high_risk': False,
                'is_low_risk': False
            }

    def _analyze_description(self, description: str, source_weight: float) -> float:
        """分析描述文本，计算描述评分"""
        if not description:
            return 40 * source_weight

        description_lower = description.lower()

        # 高危关键词
        high_risk_keywords = [
            'exploit', '漏洞利用', '0day', 'zero-day',
            'shell', 'reverse', '反弹',
            'download', '下载', 'upload', '上传',
            'crypto', '加密', 'ransomware', '勒索',
            'privilege', '权限', 'escalation', '提权',
            'lateral', '横向', 'movement', '移动'
        ]

        # 中危关键词
        medium_risk_keywords = [
            'unusual', '异常', 'suspicious', '可疑',
            'unauthorized', '未授权', 'unknown', '未知',
            'multiple', '多次', 'batch', '批量',
            'outside', '外部', 'foreign', '境外'
        ]

        # 低危关键词
        low_risk_keywords = [
            'normal', '正常', 'routine', '例行',
            'scheduled', '计划', 'regular', '定期',
            'maintenance', '维护', 'update', '更新'
        ]

        score = 50 * source_weight  # 基础分

        for keyword in high_risk_keywords:
            if keyword in description_lower:
                score += 15 * source_weight
                break

        for keyword in medium_risk_keywords:
            if keyword in description_lower:
                score += 8 * source_weight
                break

        for keyword in low_risk_keywords:
            if keyword in description_lower:
                score -= 10 * source_weight
                break

        # 限制分数范围
        return max(0, min(100, score))

    def _detect_false_positive(self, description: str, risk_tags: List[str]) -> float:
        """
        检测误报风险

        Args:
            description: 事件描述
            risk_tags: 风险标签

        Returns:
            误报风险值 (0.0-1.0)，越高越可能是误报
        """
        import re

        if not description:
            return 0.3  # 无描述信息，中等误报风险

        description_lower = description.lower()
        false_positive_score = 0.0

        # 检查误报特征模式
        for pattern in self.false_positive_patterns:
            if re.search(pattern, description_lower, re.IGNORECASE):
                false_positive_score += 0.3
                logger.info(f"检测到误报特征: {pattern}")

        # 检查低危标签
        low_risk_tags = ['配置错误', '弱密码', '扫描探测', '网络异常']
        for tag in risk_tags:
            if tag in low_risk_tags:
                false_positive_score += 0.2

        # 限制误报风险范围
        return min(1.0, false_positive_score)

    def _calculate_final_score(self, source_score: float, tag_score: float,
                               description_score: float, false_positive_risk: float) -> float:
        """计算最终评分"""
        # 加权平均：标签评分占40%，描述评分占30%，数据源占20%，误报风险占10%
        weighted_score = (
            tag_score * 0.4 +
            description_score * 0.3 +
            source_score * 0.2
        )

        # 误报风险调整：误报风险越高，最终评分越低
        adjusted_score = weighted_score * (1.0 - false_positive_risk * 0.5)

        # 限制分数范围
        return max(0, min(100, adjusted_score))

    def _calculate_confidence(self, source_score: float, tag_score: float,
                             description_score: float, false_positive_risk: float) -> float:
        """计算评分置信度"""
        # 置信度基于多个因素
        confidence_factors = []

        # 数据源置信度
        source_confidence = min(1.0, source_score / 100)
        confidence_factors.append(source_confidence)

        # 标签一致性：如果标签评分和描述评分相近，置信度高
        score_difference = abs(tag_score - description_score)
        consistency_confidence = max(0.0, 1.0 - score_difference / 100)
        confidence_factors.append(consistency_confidence)

        # 误报风险：误报风险越低，置信度越高
        false_positive_confidence = 1.0 - false_positive_risk
        confidence_factors.append(false_positive_confidence)

        # 平均置信度
        avg_confidence = sum(confidence_factors) / len(confidence_factors)

        # 限制置信度范围
        return max(0.0, min(1.0, avg_confidence))

# 创建全局评分引擎实例
risk_engine = RiskScoringEngine()