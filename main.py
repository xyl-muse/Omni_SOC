# main.py
from app.core.graph import app

def run_test():
    # 使用你提供给我的那个真实告警示例
    mock_alert = {
        "name": "主机存在普通病毒，同时发现终端恶意行为",
        "devSourceName": "EDR (宁夏电池_EDR-6616557727)",
        "riskTag": ["执行", "探测", "普通病毒"],
        "description": "通过命令查询网络连接状态;通过多个命令探测主机信息",
        # ... 其他字段可以暂时省略或保留
    }

    initial_state = {
        "raw_alert": mock_alert,
        "evidence_pool": [],
        "thought_log": [],
        "risk_score": 0,
        "status": "start",
        "next_action": None,
        "final_report": None
    }

    print("--- Omni_SOC 系统启动 ---")
    for event in app.stream(initial_state):
        pass # graph 内部的 print 会显示进度
    print("--- 任务处理完成 ---")

if __name__ == "__main__":
    run_test()