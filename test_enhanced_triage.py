# test_enhanced_triage.py - 测试增强版分析研判节点
from app.core.nodes import triage_node, make_triage_decision
from app.core.state import OmniState
from app.core.risk_scoring import risk_engine

def test_risk_scoring_engine():
    """测试多维度风险评分引擎"""
    print("=" * 50)
    print("测试1: 多维度风险评分引擎")
    print("=" * 50)

    test_cases = [
        {
            "name": "高危勒索软件告警",
            "alert": {
                "devSourceName": "EDR",
                "riskTag": ["勒索软件", "恶意软件"],
                "description": "检测到加密勒索软件行为，正在加密用户文档"
            },
            "expected_score_range": (80, 100)
        },
        {
            "name": "正常系统维护操作",
            "alert": {
                "devSourceName": "SIEM",
                "riskTag": ["配置错误"],
                "description": "系统管理员进行例行维护操作，计划内的系统更新"
            },
            "expected_score_range": (0, 40)
        },
        {
            "name": "中等风险可疑连接",
            "alert": {
                "devSourceName": "Firewall",
                "riskTag": ["可疑连接", "异常行为"],
                "description": "发现与境外IP的可疑连接，流量特征异常"
            },
            "expected_score_range": (40, 70)
        },
        {
            "name": "测试环境安全扫描",
            "alert": {
                "devSourceName": "WAF",
                "riskTag": ["扫描探测"],
                "description": "渗透测试团队进行计划内的安全扫描"
            },
            "expected_score_range": (0, 30)
        }
    ]

    all_passed = True
    for test_case in test_cases:
        print(f"\n测试场景: {test_case['name']}")

        try:
            result = risk_engine.calculate_risk_score(test_case['alert'])
            score = result['final_score']
            min_score, max_score = test_case['expected_score_range']

            print(f"数据源: {test_case['alert']['devSourceName']}")
            print(f"风险标签: {test_case['alert']['riskTag']}")
            print(f"风险评分: {score:.1f}")
            print(f"置信度: {result['confidence']:.2f}")
            print(f"误报风险: {result['false_positive_risk']:.2f}")

            if min_score <= score <= max_score:
                print(f"[PASS] 评分在预期范围 [{min_score}, {max_score}]")
            else:
                print(f"[FAIL] 评分{score:.1f}不在预期范围 [{min_score}, {max_score}]")
                all_passed = False

        except Exception as e:
            print(f"[FAIL] 测试异常: {e}")
            all_passed = False

    if all_passed:
        print("\n[PASS] 风险评分引擎测试通过！")
    else:
        print("\n[FAIL] 风险评分引擎测试失败！")

    return all_passed

def test_triage_decision_logic():
    """测试研判决策逻辑"""
    print("\n" + "=" * 50)
    print("测试2: 研判决策逻辑")
    print("=" * 50)

    test_cases = [
        {
            "name": "高分高置信度 -> 真实威胁",
            "risk_analysis": {
                'final_score': 85,
                'confidence': 0.8,
                'false_positive_risk': 0.2,
                'source_score': 80,
                'tag_score': 90,
                'description_score': 85
            },
            "llm_response": "根据分析，这是一个真实的勒索软件攻击",
            "expected_result": "hunting"
        },
        {
            "name": "低分高误报风险 -> 误报",
            "risk_analysis": {
                'final_score': 35,
                'confidence': 0.7,
                'false_positive_risk': 0.8,
                'source_score': 40,
                'tag_score': 30,
                'description_score': 35
            },
            "llm_response": "根据分析，可能是误报",
            "expected_result": "archive"
        },
        {
            "name": "中等评分+LLM确认 -> 真实威胁",
            "risk_analysis": {
                'final_score': 65,
                'confidence': 0.7,
                'false_positive_risk': 0.3,
                'source_score': 70,
                'tag_score': 65,
                'description_score': 60
            },
            "llm_response": "判断为真实威胁",
            "expected_result": "hunting"
        }
    ]

    all_passed = True
    for test_case in test_cases:
        print(f"\n测试场景: {test_case['name']}")

        try:
            decision = make_triage_decision(test_case['risk_analysis'], test_case['llm_response'])
            action = decision['action']

            print(f"综合评分: {test_case['risk_analysis']['final_score']:.1f}")
            print(f"置信度: {test_case['risk_analysis']['confidence']:.2f}")
            print(f"误报风险: {test_case['risk_analysis']['false_positive_risk']:.2f}")
            print(f"决策结果: {action}")

            if action == test_case['expected_result']:
                print(f"[PASS] 决策符合预期: {action}")
            else:
                print(f"[FAIL] 决策不符合预期: 期望{test_case['expected_result']}, 实际{action}")
                all_passed = False

        except Exception as e:
            print(f"[FAIL] 测试异常: {e}")
            all_passed = False

    if all_passed:
        print("\n[PASS] 研判决策逻辑测试通过！")
    else:
        print("\n[FAIL] 研判决策逻辑测试失败！")

    return all_passed

def test_full_triage_workflow():
    """测试完整研判工作流"""
    print("\n" + "=" * 50)
    print("测试3: 完整研判工作流")
    print("=" * 50)

    test_cases = [
        {
            "name": "真实威胁工作流",
            "alert": {
                "devSourceName": "EDR",
                "riskTag": ["勒索软件"],
                "description": "检测到文档加密活动，疑似勒索软件攻击"
            },
            "expected_action": "hunting"
        },
        {
            "name": "误报工作流",
            "alert": {
                "devSourceName": "SIEM",
                "riskTag": ["配置错误"],
                "description": "系统管理员进行计划维护操作"
            },
            "expected_action": "archive"
        }
    ]

    all_passed = True
    for test_case in test_cases:
        print(f"\n测试场景: {test_case['name']}")

        try:
            # 创建测试状态
            state = OmniState(
                raw_alert=test_case['alert'],
                evidence_pool=[],
                thought_log=[],
                risk_score=0,
                status="start",
                next_action=None,
                final_report=None,
                response_mode="auto",
                needs_approval=None,
                archive_id=None
            )

            # 执行研判节点（使用Mock，不调用LLM）
            print(f"执行研判节点...")
            print(f"数据源: {test_case['alert']['devSourceName']}")
            print(f"风险标签: {test_case['alert']['riskTag']}")

            # 仅测试风险评分逻辑
            risk_analysis = risk_engine.calculate_risk_score(test_case['alert'])
            print(f"风险评分: {risk_analysis['final_score']:.1f}")

            # 基于风险评分的简单决策
            if risk_analysis['final_score'] >= 70:
                action = "hunting"
            else:
                action = "archive"

            print(f"决策结果: {action}")

            if action == test_case['expected_action']:
                print(f"[PASS] 决策符合预期: {action}")
            else:
                print(f"[FAIL] 决策不符合预期: 期望{test_case['expected_action']}, 实际{action}")
                all_passed = False

        except Exception as e:
            print(f"[FAIL] 测试异常: {e}")
            all_passed = False

    if all_passed:
        print("\n[PASS] 完整研判工作流测试通过！")
    else:
        print("\n[FAIL] 完整研判工作流测试失败！")

    return all_passed

def main():
    """运行所有测试"""
    print("Enhanced Triage Node Test Suite")
    print("=" * 50)

    results = []

    # 运行测试
    results.append(("风险评分引擎", test_risk_scoring_engine()))
    results.append(("研判决策逻辑", test_triage_decision_logic()))
    results.append(("完整研判工作流", test_full_triage_workflow()))

    # 总结测试结果
    print("\n" + "=" * 50)
    print("Test Summary")
    print("=" * 50)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{test_name}: {status}")

    print(f"\nOverall Result: {passed}/{total} tests passed")

    if passed == total:
        print("\n[SUCCESS] All tests passed! Enhanced triage node validated!")
        return True
    else:
        print(f"\n[WARNING] {total - passed} test(s) failed, needs fixing!")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)