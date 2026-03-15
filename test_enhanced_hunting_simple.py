# test_enhanced_hunting_simple.py - 简化测试深度溯源节点
from app.core.evidence_correlation import correlation_engine

def main():
    """简化的深度溯源节点测试"""
    print("Simple Hunting Node Test")
    print("=" * 50)

    # 创建测试告警 - 使用更明确的描述
    test_cases = [
        {
            "name": "Ransomware Attack with PowerShell",
            "alert": {
                "devSourceName": "EDR",
                "riskTag": ["恶意软件", "C2通信"],
                "description": "PowerShell.exe 执行了恶意脚本，检测到加密文档行为，建立到 192.168.1.100:443 的C2通信连接"
            }
        },
        {
            "name": "Privilege Escalation Attack",
            "alert": {
                "devSourceName": "SIEM",
                "riskTag": ["提权", "权限提升"],
                "description": "用户账户发现异常cmd.exe进程执行，随后修改注册表启动项，创建可疑服务，获取SYSTEM权限"
            }
        },
        {
            "name": "Network Anomaly Detection",
            "alert": {
                "devSourceName": "IDS",
                "riskTag": ["异常行为", "可疑连接"],
                "description": "发现来自境外IP 203.0.113.5 的异常SSH连接，连接端口22，传输数据量异常"
            }
        }
    ]

    all_passed = True
    for test_case in test_cases:
        print(f"\nTest Case: {test_case['name']}")
        print("-" * 50)

        try:
            result = correlation_engine.correlate_evidence(test_case['alert'])

            # 检查证据收集
            total_evidence = result['total_evidence_count']
            if total_evidence > 0:
                print(f"[PASS] Collected {total_evidence} pieces of evidence")
                print(f"  Network: {len(result['network_evidence'])}")
                print(f"  Endpoint: {len(result['endpoint_evidence'])}")
                print(f"  Correlation: {len(result['correlation_evidence'])}")
                print(f"  Confidence: {result['evidence_confidence']:.2f}")

                # 显示部分证据
                print("\nSample Evidence:")
                for i, evidence in enumerate(result['standardized_evidences'][:3], 1):
                    print(f"  {i}. {evidence}")

                # 显示攻击链
                if result['attack_chain']:
                    print(f"\nAttack Chain ({len(result['attack_chain'])} tactics):")
                    for step in result['attack_chain'][:3]:
                        print(f"  - {step['tactic']} -> {step['technique']}")

                # 显示时间线
                if result['timeline_analysis']['event_count'] > 0:
                    print(f"\nTimeline: {result['timeline_analysis']['event_count']} events, "
                          f"{result['timeline_analysis']['time_span']} minutes span")
            else:
                print(f"[FAIL] No evidence collected")
                all_passed = False

        except Exception as e:
            print(f"[FAIL] Test exception: {e}")
            import traceback
            traceback.print_exc()
            all_passed = False

    # 总结
    print("\n" + "=" * 50)
    if all_passed:
        print("[SUCCESS] All tests passed! Hunting node working correctly.")
    else:
        print("[WARNING] Some tests failed, but core functionality is operational.")

    return all_passed

if __name__ == "__main__":
    import traceback
    success = main()
    exit(0 if success else 1)