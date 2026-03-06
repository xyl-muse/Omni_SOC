# main.py 完整修复版
import sys
import os

# 1. 强制将项目根目录加入Python搜索路径（解决导入问题）
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

# 2. 导入必要模块（包括OmniState类）
from app.core.graph import app
from app.core.state import OmniState  # 直接导入OmniState类

def run_test():
    # 模拟告警数据
    mock_alert = {
        "name": "主机存在普通病毒，同时发现终端恶意行为",
        "devSourceName": "EDR (宁夏电池_EDR-6616557727)",
        "riskTag": ["执行", "探测", "普通病毒"],
        "description": "通过命令查询网络连接状态;通过多个命令探测主机信息",
    }

    # 3. 关键修复：创建OmniState实例（而非普通字典）
    # 假设OmniState类支持通过关键字参数初始化（SOC项目通用设计）
    initial_state = OmniState(
        raw_alert=mock_alert,
        evidence_pool=[],
        thought_log=[],
        risk_score=0,
        status="start",
        next_action=None,
        final_report=None
    )

    print("--- Omni_SOC 系统启动 ---")
    # 4. 传入OmniState实例，解决类型不匹配
    for event in app.stream(initial_state):
        pass  # graph 内部的 print 会显示进度
    print("--- 任务处理完成 ---")

if __name__ == "__main__":
    # 调试：打印路径，确认根目录已加入
    print(f"项目根目录已加入：{PROJECT_ROOT}")
    run_test()