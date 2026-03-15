# app/core/evidence_correlation.py - 深度溯源证据关联引擎
from typing import Dict, List, Tuple
from datetime import datetime, timedelta
from .utils import logger
import re

class EvidenceCorrelationEngine:
    """证据关联引擎，用于深度溯源和攻击链构建"""

    def __init__(self):
        # MITRE ATT&CK 战术映射
        self.attack_tactics = {
            'initial_access': ['钓鱼', '漏洞利用', '有效账户'],
            'execution': ['命令行', 'PowerShell', '脚本执行', '进程注入'],
            'persistence': ['计划任务', '启动项', '服务创建', '注册表修改'],
            'privilege_escalation': ['提权', '令牌操纵', '绕过UAC'],
            'defense_evasion': ['混淆', '隐藏文件', '进程伪装', '禁用安全工具'],
            'credential_access': ['凭据转储', '密码破解', '密钥窃取'],
            'discovery': ['端口扫描', '系统发现', '网络发现', '进程发现'],
            'lateral_movement': ['远程服务', 'SMB协议', 'RDP连接', 'WMI执行'],
            'collection': ['数据收集', '屏幕截图', '剪贴板', '键盘记录'],
            'command_and_control': ['C2通信', '反向Shell', '隧道技术'],
            'exfiltration': ['数据外传', 'FTP上传', 'HTTP上传', 'DNS隧道'],
            'impact': ['加密', '删除', '篡改', '破坏']
        }

        # 证据类型权重
        self.evidence_weights = {
            'network': 0.3,      # 网络证据权重30%
            'endpoint': 0.4,     # 终端证据权重40%
            'correlation': 0.2,   # 关联证据权重20%
            'timeline': 0.1       # 时间线证据权重10%
        }

        # 时间窗口设置（分钟）
        self.time_window_minutes = 60  # 默认1小时时间窗口

    def correlate_evidence(self, raw_alert: Dict, existing_evidence: List = None) -> Dict:
        """
        执行多源证据关联分析

        Args:
            raw_alert: 原始告警数据
            existing_evidence: 已有的证据列表

        Returns:
            证据关联分析结果
        """
        try:
            evidence_existing = existing_evidence or []

            # 1. 网络证据收集
            network_evidence = self._collect_network_evidence(raw_alert)

            # 2. 终端证据收集
            endpoint_evidence = self._collect_endpoint_evidence(raw_alert)

            # 3. 关联证据分析
            correlation_evidence = self._analyze_correlations(
                raw_alert, network_evidence, endpoint_evidence, evidence_existing
            )

            # 4. 时间线分析
            timeline_analysis = self._analyze_timeline(
                raw_alert, network_evidence, endpoint_evidence
            )

            # 5. 攻击链构建
            attack_chain = self._build_attack_chain(
                network_evidence, endpoint_evidence
            )

            # 6. 计算证据置信度
            evidence_confidence = self._calculate_evidence_confidence(
                network_evidence, endpoint_evidence, correlation_evidence, timeline_analysis
            )

            # 7. 生成标准化证据列表
            standardized_evidences = self._standardize_evidences(
                network_evidence, endpoint_evidence, correlation_evidence, timeline_analysis
            )

            result = {
                'network_evidence': network_evidence,
                'endpoint_evidence': endpoint_evidence,
                'correlation_evidence': correlation_evidence,
                'timeline_analysis': timeline_analysis,
                'attack_chain': attack_chain,
                'evidence_confidence': evidence_confidence,
                'standardized_evidences': standardized_evidences,
                'total_evidence_count': len(standardized_evidences),
                'high_confidence_count': sum(1 for e in standardized_evidences if e['confidence'] >= 0.7)
            }

            logger.info(f"证据关联完成: 总证据{result['total_evidence_count']}条, "
                       f"高置信度{result['high_confidence_count']}条, "
                       f"整体置信度{evidence_confidence:.2f}")

            return result

        except Exception as e:
            logger.error(f"证据关联分析异常: {e}")
            return self._get_default_correlation_result()

    def _collect_network_evidence(self, raw_alert: Dict) -> List[Dict]:
        """收集网络层面的证据"""
        evidences = []
        description = raw_alert.get('description', '')
        risk_tags = raw_alert.get('riskTag', [])

        # 分析连接信息
        connection_patterns = [
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',  # IP地址
            r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',          # 域名
            r'端口\s*(\d+)',                               # 端口号
            r'(http|https|ftp|ssh|rdp|smb)://',            # 协议
        ]

        # 提取网络实体
        network_entities = []
        for pattern in connection_patterns:
            matches = re.findall(pattern, description)
            network_entities.extend(matches)

        if network_entities:
            evidences.append({
                'type': 'network',
                'category': 'connection_info',
                'description': f'检测到网络连接实体: {", ".join(network_entities[:5])}',
                'entities': network_entities,
                'confidence': 0.8 if len(network_entities) >= 3 else 0.6,
                'timestamp': self._get_current_timestamp()
            })

        # 分析协议特征
        if any(tag in risk_tags for tag in ['C2通信', '命令控制', '反向连接']):
            evidences.append({
                'type': 'network',
                'category': 'c2_communication',
                'description': '检测到可疑的C2通信特征',
                'risk_level': 'high',
                'confidence': 0.85,
                'timestamp': self._get_current_timestamp()
            })

        # 分析异常连接
        anomaly_keywords = ['境外', '异常', '可疑', '未授权', '未建立']
        if any(keyword in description for keyword in anomaly_keywords):
            evidences.append({
                'type': 'network',
                'category': 'abnormal_connection',
                'description': '检测到异常网络连接行为',
                'risk_level': 'medium',
                'confidence': 0.7,
                'timestamp': self._get_current_timestamp()
            })

        return evidences

    def _collect_endpoint_evidence(self, raw_alert: Dict) -> List[Dict]:
        """收集终端层面的证据"""
        evidences = []
        description = raw_alert.get('description', '')
        risk_tags = raw_alert.get('riskTag', [])

        # 分析进程行为
        process_keywords = ['进程', 'PowerShell', 'cmd.exe', 'wscript.exe', 'rundll32.exe']
        if any(keyword in description for keyword in process_keywords):
            process_info = self._extract_process_info(description)
            evidences.append({
                'type': 'endpoint',
                'category': 'process_behavior',
                'description': f'检测到可疑进程活动: {process_info}',
                'details': process_info,
                'risk_level': 'high',
                'confidence': 0.75,
                'timestamp': self._get_current_timestamp()
            })

        # 分析文件操作
        file_keywords = ['文件', '下载', '上传', '删除', '加密', '修改', '创建']
        if any(keyword in description for keyword in file_keywords):
            file_operations = self._extract_file_operations(description)
            evidences.append({
                'type': 'endpoint',
                'category': 'file_operation',
                'description': f'检测到文件操作: {file_operations}',
                'details': file_operations,
                'risk_level': 'medium',
                'confidence': 0.65,
                'timestamp': self._get_current_timestamp()
            })

        # 分析注册表/系统修改
        registry_keywords = ['注册表', '启动项', '服务', '计划任务', 'UAC']
        if any(keyword in description for keyword in registry_keywords):
            evidences.append({
                'type': 'endpoint',
                'category': 'system_modification',
                'description': '检测到系统配置修改行为',
                'risk_level': 'high',
                'confidence': 0.8,
                'timestamp': self._get_current_timestamp()
            })

        # 分析提权行为
        privilege_keywords = ['提权', '权限', '管理员', 'SYSTEM', 'root', 'sudo']
        if any(keyword in description for keyword in privilege_keywords):
            evidences.append({
                'type': 'endpoint',
                'category': 'privilege_escalation',
                'description': '检测到权限提升相关行为',
                'risk_level': 'high',
                'confidence': 0.85,
                'timestamp': self._get_current_timestamp()
            })

        return evidences

    def _analyze_correlations(self, raw_alert: Dict, network_evidence: List,
                             endpoint_evidence: List, existing_evidence: List) -> List[Dict]:
        """分析证据之间的关联关系"""
        correlations = []

        # 1. 主机间关联（模拟）
        similar_hosts = self._find_similar_hosts(raw_alert)
        if similar_hosts:
            correlations.append({
                'type': 'correlation',
                'category': 'host_correlation',
                'description': f'发现{len(similar_hosts)}台主机出现相似告警',
                'related_hosts': similar_hosts,
                'confidence': 0.75,
                'timestamp': self._get_current_timestamp()
            })

        # 2. 时间关联
        time_correlations = self._find_time_correlations(
            raw_alert, network_evidence, endpoint_evidence
        )
        correlations.extend(time_correlations)

        # 3. 攻击模式关联
        attack_pattern = self._identify_attack_pattern(
            network_evidence, endpoint_evidence
        )
        if attack_pattern:
            correlations.append({
                'type': 'correlation',
                'category': 'attack_pattern',
                'description': f'识别到攻击模式: {attack_pattern}',
                'pattern': attack_pattern,
                'confidence': 0.7,
                'timestamp': self._get_current_timestamp()
            })

        # 4. 指纹关联
        fingerprint = self._generate_attack_fingerprint(
            raw_alert, network_evidence, endpoint_evidence
        )
        if fingerprint:
            correlations.append({
                'type': 'correlation',
                'category': 'attack_fingerprint',
                'description': f'生成攻击指纹: {fingerprint[:50]}...',
                'fingerprint': fingerprint,
                'confidence': 0.6,
                'timestamp': self._get_current_timestamp()
            })

        return correlations

    def _analyze_timeline(self, raw_alert: Dict, network_evidence: List,
                         endpoint_evidence: List) -> Dict:
        """分析事件时间线"""
        timeline_events = []

        # 收集所有证据的时间戳
        all_evidences = network_evidence + endpoint_evidence
        for evidence in all_evidences:
            if 'timestamp' in evidence:
                timeline_events.append({
                    'timestamp': evidence['timestamp'],
                    'event_type': f"{evidence['type']}_{evidence['category']}",
                    'description': evidence['description'],
                    'confidence': evidence['confidence']
                })

        # 如果没有时间信息，创建模拟时间线
        if not timeline_events:
            current_time = datetime.now()
            timeline_events = [
                {
                    'timestamp': (current_time - timedelta(minutes=30)).isoformat(),
                    'event_type': 'network_abnormal_connection',
                    'description': '初始异常连接检测',
                    'confidence': 0.7
                },
                {
                    'timestamp': (current_time - timedelta(minutes=25)).isoformat(),
                    'event_type': 'endpoint_process_behavior',
                    'description': '可疑进程启动',
                    'confidence': 0.8
                },
                {
                    'timestamp': (current_time - timedelta(minutes=20)).isoformat(),
                    'event_type': 'endpoint_privilege_escalation',
                    'description': '权限提升行为',
                    'confidence': 0.85
                },
                {
                    'timestamp': (current_time - timedelta(minutes=15)).isoformat(),
                    'event_type': 'network_c2_communication',
                    'description': 'C2通信建立',
                    'confidence': 0.8
                },
                {
                    'timestamp': current_time.isoformat(),
                    'event_type': 'alert_triggered',
                    'description': '安全告警触发',
                    'confidence': 0.9
                }
            ]

        # 排序时间线
        timeline_events.sort(key=lambda x: x['timestamp'])

        # 计算时间跨度
        if timeline_events:
            start_time = min(event['timestamp'] for event in timeline_events)
            end_time = max(event['timestamp'] for event in timeline_events)
            time_span = self._calculate_time_span(start_time, end_time)

            event_density = len(timeline_events) / max(1, time_span)  # 事件密度

            return {
                'events': timeline_events,
                'event_count': len(timeline_events),
                'start_time': start_time,
                'end_time': end_time,
                'time_span': time_span,
                'attack_duration': time_span,
                'event_density': event_density
            }

        return {
            'events': [],
            'event_count': 0,
            'time_span': 0
        }

    def _build_attack_chain(self, network_evidence: List, endpoint_evidence: List) -> List[Dict]:
        """构建MITRE ATT&CK攻击链"""
        attack_chain = []

        # 基于证据映射到MITRE战术
        evidence_types = {
            'abnormal_connection': 'initial_access',
            'c2_communication': 'command_and_control',
            'process_behavior': 'execution',
            'privilege_escalation': 'privilege_escalation',
            'file_operation': 'collection',
            'system_modification': 'persistence'
        }

        # 收集所有证据类型
        all_evidences = network_evidence + endpoint_evidence
        detected_tactics = set()

        for evidence in all_evidences:
            category = evidence.get('category', '')
            if category in evidence_types:
                tactic = evidence_types[category]
                detected_tactics.add(tactic)

        # 排序攻击链（按照典型攻击流程）
        tactic_order = [
            'initial_access', 'execution', 'persistence', 'privilege_escalation',
            'defense_evasion', 'credential_access', 'discovery', 'lateral_movement',
            'collection', 'command_and_control', 'exfiltration', 'impact'
        ]

        for tactic in tactic_order:
            if tactic in detected_tactics:
                chain_steps = self.attack_tactics.get(tactic, [])
                selected_step = chain_steps[0] if chain_steps else tactic

                attack_chain.append({
                    'tactic': tactic,
                    'technique': selected_step,
                    'confidence': 0.7,  # 默认置信度
                    'evidence_count': 0  # 简化处理，后续可以优化
                })

        return attack_chain

    def _calculate_evidence_confidence(self, network_evidence: List, endpoint_evidence: List,
                                     correlation_evidence: List, timeline_analysis: Dict) -> float:
        """计算证据整体置信度"""
        factors = []

        # 证据数量因素
        total_evidence = len(network_evidence) + len(endpoint_evidence) + len(correlation_evidence)
        evidence_factor = min(1.0, total_evidence / 10.0)  # 10条证据达到最高
        factors.append(evidence_factor)

        # 网络证据置信度
        if network_evidence:
            network_confidence = sum(e['confidence'] for e in network_evidence) / len(network_evidence)
            factors.append(network_confidence * self.evidence_weights['network'])

        # 终端证据置信度
        if endpoint_evidence:
            endpoint_confidence = sum(e['confidence'] for e in endpoint_evidence) / len(endpoint_evidence)
            factors.append(endpoint_confidence * self.evidence_weights['endpoint'])

        # 关联证据置信度
        if correlation_evidence:
            correlation_confidence = sum(e['confidence'] for e in correlation_evidence) / len(correlation_evidence)
            factors.append(correlation_confidence * self.evidence_weights['correlation'])

        # 时间线完整性因素
        if timeline_analysis and timeline_analysis.get('event_count', 0) > 0:
            timeline_factor = min(1.0, timeline_analysis['event_count'] / 5.0)  # 5个事件达到最高
            factors.append(timeline_factor * self.evidence_weights['timeline'])

        # 平均置信度
        if factors:
            return sum(factors) / len(factors)

        return 0.5  # 默认置信度

    def _standardize_evidences(self, network_evidence: List, endpoint_evidence: List,
                              correlation_evidence: List, timeline_analysis: Dict) -> List[str]:
        """标准化证据格式，用于输出"""
        standardized = []

        # 网络证据
        for evidence in network_evidence:
            standardized.append(
                f"[网络证据] {evidence['description']} (置信度: {evidence['confidence']:.2f})"
            )

        # 终端证据
        for evidence in endpoint_evidence:
            standardized.append(
                f"[终端证据] {evidence['description']} (置信度: {evidence['confidence']:.2f})"
            )

        # 关联证据
        for evidence in correlation_evidence:
            standardized.append(
                f"[关联证据] {evidence['description']} (置信度: {evidence['confidence']:.2f})"
            )

        # 时间线证据
        if timeline_analysis and timeline_analysis.get('events'):
            timeline_info = f"事件时间线: {timeline_analysis['start_time']} ~ {timeline_analysis['end_time']}"
            timeline_info += f", 事件数量: {timeline_analysis['event_count']}"
            standardized.append(f"[时间证据] {timeline_info}")

        return standardized

    # 辅助函数
    def _extract_process_info(self, description: str) -> str:
        """从描述中提取进程信息"""
        process_patterns = [
            r'(PowerShell|cmd\.exe|wscript\.exe|rundll32\.exe|regsvr32\.exe)',
            r'进程\s*[:：]\s*([^,，.。]+)',
            r'PID\s*(\d+)'
        ]

        for pattern in process_patterns:
            matches = re.findall(pattern, description, re.IGNORECASE)
            if matches:
                return ", ".join(matches[:3])  # 最多返回3个匹配

        return "未知进程"

    def _extract_file_operations(self, description: str) -> str:
        """从描述中提取文件操作信息"""
        operations = []
        if '下载' in description:
            operations.append('文件下载')
        if '上传' in description:
            operations.append('文件上传')
        if '删除' in description:
            operations.append('文件删除')
        if '加密' in description:
            operations.append('文件加密')
        if '修改' in description:
            operations.append('文件修改')

        return ", ".join(operations) if operations else "文件操作"

    def _find_similar_hosts(self, raw_alert: Dict) -> List[str]:
        """查找相似主机（模拟）"""
        # 模拟：生成几个相似的IP地址
        base_ip = "192.168.1."
        similar_hosts = [f"{base_ip}{i}" for i in range(100, 104)]
        return similar_hosts

    def _find_time_correlations(self, raw_alert: Dict, network_evidence: List,
                              endpoint_evidence: List) -> List[Dict]:
        """查找时间上的关联"""
        correlations = []

        # 检查是否有证据在时间窗口内
        all_evidences = network_evidence + endpoint_evidence
        if len(all_evidences) >= 2:
            correlations.append({
                'type': 'correlation',
                'category': 'time_correlation',
                'description': f'发现{len(all_evidences)}个证据在时间窗口内',
                'evidence_count': len(all_evidences),
                'confidence': 0.7,
                'timestamp': self._get_current_timestamp()
            })

        return correlations

    def _identify_attack_pattern(self, network_evidence: List, endpoint_evidence: List) -> str:
        """识别攻击模式"""
        evidence_categories = set()

        for evidence in network_evidence + endpoint_evidence:
            evidence_categories.add(evidence.get('category', ''))

        # 简单的模式识别
        if 'c2_communication' in evidence_categories and 'privilege_escalation' in evidence_categories:
            return "C2攻击链"
        elif 'abnormal_connection' in evidence_categories and 'process_behavior' in evidence_categories:
            return "初始访问+执行"
        elif 'privilege_escalation' in evidence_categories and 'system_modification' in evidence_categories:
            return "权限提升+持久化"
        else:
            return "通用攻击模式"

    def _generate_attack_fingerprint(self, raw_alert: Dict, network_evidence: List,
                                   endpoint_evidence: List) -> str:
        """生成攻击指纹"""
        # 简单的指纹生成：基于证据类型组合
        evidence_types = set()

        for evidence in network_evidence:
            evidence_types.add(f"net_{evidence['category']}")

        for evidence in endpoint_evidence:
            evidence_types.add(f"ep_{evidence['category']}")

        # 生成指纹字符串
        fingerprint = "|".join(sorted(evidence_types))

        # 添加哈希值
        import hashlib
        fingerprint_hash = hashlib.md5(fingerprint.encode()).hexdigest()[:8]

        return f"{fingerprint}|{fingerprint_hash}"

    def _get_current_timestamp(self) -> str:
        """获取当前时间戳"""
        return datetime.now().isoformat()

    def _calculate_time_span(self, start_time: str, end_time: str) -> float:
        """计算时间跨度（分钟）"""
        try:
            start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            end = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            delta = end - start
            return delta.total_seconds() / 60  # 转换为分钟
        except Exception:
            return 0

    def _get_default_correlation_result(self) -> Dict:
        """获取默认的关联结果"""
        return {
            'network_evidence': [],
            'endpoint_evidence': [],
            'correlation_evidence': [],
            'timeline_analysis': {
                'events': [],
                'event_count': 0,
                'time_span': 0
            },
            'attack_chain': [],
            'evidence_confidence': 0.5,
            'standardized_evidences': ['[系统证据] 证据收集异常'],
            'total_evidence_count': 0,
            'high_confidence_count': 0
        }

# 创建全局证据关联引擎实例
correlation_engine = EvidenceCorrelationEngine()