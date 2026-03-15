# test_enhanced_hunting.py - 测试增强版深度溯源节点
from app.core.nodes import hunting_node
from app.core.state import OmniState
from app.core.evidence_correlation import correlation_engine

def test_evidence_correlation():
    """测试证据关联引擎"""
    print("=" * 50)
    print("Test 1: Evidence Correlation Engine")
    print("=" * 50)

    test_cases = [
        {
            "name": "Complex Ransomware Attack",
            "alert": {
                "devSourceName": "EDR",
                "riskTag": ["勒索软件", "恶意软件", "C2通信"],
                "description": "检测到勒索软件加密文档，发现异常PowerShell进程，建立C2通信连接"
            }
        },
        {
            "name": "Suspicious Network Connection",
            "alert": {
                "devSourceName": "Firewall",
                "riskTag": ["可疑连接", "异常行为"],
                "description": "发现与境外IP的可疑连接，流量特征异常，包含命令和控制通信特征"
            }
        },
        {
            "name": "Privilege Escalation Attempt",
            "alert": {
                "devSourceName": "IDS",
                "riskTag": ["提权", "权限提升"],
                "description": "检测到用户尝试提升权限，修改注册表启动项，创建可疑服务"
            }
        }
    ]

    all_passed = True
    for test_case in test_cases:
        print(f"\nTest Case: {test_case['name']}")

        try:
            result = correlation_engine.correlate_evidence(test_case['alert'])

            print(f"Network Evidence: {len(result['network_evidence'])} items")
            print(f"Endpoint Evidence: {len(result['endpoint_evidence'])} items")
            print(f"Correlation Evidence: {len(result['correlation_evidence'])} items")
            print(f"Total Evidence: {result['total_evidence_count']} items")
            print(f"High Confidence: {result['high_confidence_count']} items")
            print(f"Overall Confidence: {result['evidence_confidence']:.2f}")
            print(f"Attack Chain: {len(result['attack_chain'])} tactics")

            # 基本验证
            if result['total_evidence_count'] > 0:
                print("[PASS] Evidence collection successful")
            else:
                print("[FAIL] No evidence collected")
                all_passed = False

            if result['evidence_confidence'] > 0:
                print("[PASS] Confidence calculated")
            else:
                print("[FAIL] Invalid confidence")
                all_passed = False

        except Exception as e:
            print(f"[FAIL] Test exception: {e}")
            all_passed = False

    if all_passed:
        print("\n[PASS] Evidence correlation engine test passed!")
    else:
        print("\n[FAIL] Evidence correlation engine test failed!")

    return all_passed

def test_attack_chain_building():
    """测试攻击链构建"""
    print("\n" + "=" * 50)
    print("Test 2: Attack Chain Building")
    print("=" * 50)

    test_cases = [
        {
            "name": "Full Attack Chain",
            "alert": {
                "devSourceName": "EDR",
                "riskTag": ["C2通信", "提权", "恶意软件"],
                "description": "异常连接触发C2通信，随后进程执行，发现权限提升和系统修改"
            }
        },
        {
            "name": "Partial Attack Chain",
            "alert": {
                "devSourceName": "SIEM",
                "riskTag": ["异常行为"],
                "description": "发现异常进程启动，但后续证据不足"
            }
        }
    ]

    all_passed = True
    for test_case in test_cases:
        print(f"\nTest Case: {test_case['name']}")

        try:
            result = correlation_engine.correlate_evidence(test_case['alert'])
            attack_chain = result['attack_chain']

            print(f"Attack Chain Length: {len(attack_chain)} tactics")

            if attack_chain:
                print("Attack Chain Steps:")
                for i, step in enumerate(attack_chain, 1):
                    print(f"  {i}. {step['tactic']} -> {step['technique']}")

            # 验证攻击链
            if len(attack_chain) > 0:
                print("[PASS] Attack chain built successfully")
            else:
                print("[FAIL] Empty attack chain")
                all_passed = False

        except Exception as e:
            print(f"[FAIL] Test exception: {e}")
            all_passed = False

    if all_passed:
        print("\n[PASS] Attack chain building test passed!")
    else:
        print("\n[FAIL] Attack chain building test failed!")

    return all_passed

def test_timeline_analysis():
    """测试时间线分析"""
    print("\n" + "=" * 50)
    print("Test 3: Timeline Analysis")
    print("=" * 50)

    test_alert = {
        "devSourceName": "EDR",
        "riskTag": ["勒索软件"],
        "description": "勒索软件攻击事件"
    }

    try:
        result = correlation_engine.correlate_evidence(test_alert)
        timeline = result['timeline_analysis']

        print(f"Timeline Events: {timeline['event_count']}")
        print(f"Time Span: {timeline['time_span']} minutes")

        # 检查是否有event_density键
        event_density = timeline.get('event_density', 0)
        if event_density:
            print(f"Event Density: {event_density:.2f} events/minute")

        if timeline['event_count'] > 0:
            print("\nTimeline Events:")
            timeline_events = timeline.get('events', [])
            for i, event in enumerate(timeline_events[:5], 1):  # 只显示前5个事件
                print(f"  {i}. {event['timestamp']} - {event['event_type']}")
                print(f"     {event['description']}")

        # 验证时间线
        if timeline['event_count'] > 0:
            print("\n[PASS] Timeline analysis successful")
            return True
        else:
            print("\n[FAIL] Empty timeline")
            return False

    except Exception as e:
        print(f"\n[FAIL] Test exception: {e}")
        return False

def test_full_hunting_workflow():
    """测试完整溯源工作流"""
    print("\n" + "=" * 50)
    print("Test 4: Full Hunting Workflow")
    print("=" * 50)

    test_alert = {
        "devSourceName": "EDR",
        "riskTag": ["勒索软件", "恶意软件", "C2通信"],
        "description": "检测到勒索软件加密活动，发现异常PowerShell进程，建立C2通信连接"
    }

    try:
        # 创建测试状态
        state = OmniState(
            raw_alert=test_alert,
            evidence_pool=[],
            thought_log=[],
            risk_score=85,
            status="hunting",
            next_action=None,
            final_report=None,
            response_mode="auto",
            needs_approval=None,
            archive_id=None
        )

        print("Executing hunting node...")

        # 执行溯源节点
        result = hunting_node(state)

        print(f"Evidence Pool Size: {len(result['evidence_pool'])}")
        print(f"Next Action: {result['next_action']}")
        print(f"Status: {result['status']}")

        if 'attack_chain' in result:
            print(f"Attack Chain: {len(result['attack_chain'])} tactics")

        if 'evidence_confidence' in result:
            print(f"Evidence Confidence: {result['evidence_confidence']:.2f}")

        # 验证结果
        if (result['next_action'] == 'response' and
            result['status'] == 'hunting_completed' and
            len(result['evidence_pool']) > 0):
            print("\n[PASS] Full hunting workflow test passed!")
            return True
        else:
            print("\n[FAIL] Unexpected workflow result")
            return False

    except Exception as e:
        print(f"\n[FAIL] Test exception: {e}")
        return False

def main():
    """运行所有测试"""
    print("Enhanced Hunting Node Test Suite")
    print("=" * 50)

    results = []

    # 运行测试
    results.append(("Evidence Correlation Engine", test_evidence_correlation()))
    results.append(("Attack Chain Building", test_attack_chain_building()))
    results.append(("Timeline Analysis", test_timeline_analysis()))
    results.append(("Full Hunting Workflow", test_full_hunting_workflow()))

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
        print("\n[SUCCESS] All tests passed! Enhanced hunting node validated!")
        return True
    else:
        print(f"\n[WARNING] {total - passed} test(s) failed, needs fixing!")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)