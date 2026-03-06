# Omni_SOC: AI-Driven Autonomous Security Operations Center

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-LangGraph-orange.svg)](https://github.com/langchain-ai/langgraph)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Omni_SOC** 是一个基于 Agentic 工作流构建的下一代自动化安全运营平台原型。它利用 **LangGraph** 的状态机机制，模拟安全专家对告警（Alert）的研判、深度调查（Hunting）及响应（Response）全生命周期流程。

---

## 🌟 核心特性

- **智能分诊 (Autonomous Triage)**: 利用 LLM (GPT-4o) 自动解析复杂安全告警，识别风险标签。
- **动态路径决策**: 根据告警严重程度和上下文，动态决定进入“深度威胁猎杀”或“直接响应报告”流程。
- **状态感知型架构**: 基于 `OmniState` 的数字卷宗系统，确保在复杂的分析链路中证据（Evidence）不丢失、逻辑可追溯。
- **企业级工程化实现**: 严格遵循 Python 模块化规范，支持复杂的绝对路径导入及环境自适应启动。

## 🏗️ 系统架构

项目采用模块化设计，将安全专家的思维逻辑解构为独立的节点（Nodes）：



1. **Triage Node**: 初始研判，评估风险分值。
2. **Hunting Node**: 针对高危告警进行自动化取证（如进程分析、网络连接检查）。
3. **Response Node**: 汇总所有调查证据，生成结构化的处置建议报告。

## 🚀 快速开始

### 1. 环境准备
确保你的环境中已安装 Python 3.10+。

```bash
git clone [https://github.com/xyl-muse/Omni_SOC.git](https://github.com/xyl-muse/Omni_SOC.git)
cd Omni_SOC
pip install -r requirements.txt
```

### 2. 配置密钥
在根目录创建 .env 文件，并配置你的 API 密钥：
```
OPENAI_API_KEY=sk-your-key-here
```

### 3. 运行点火测试
```
python main.py
```

## 📂 项目结构
```text
Omni_SOC/
├── app/
│   └── core/
│       ├── __init__.py
│       ├── graph.py    # 状态机拓扑定义
│       ├── nodes.py    # 业务处理逻辑 (AI Brain)
│       ├── state.py    # 状态结构定义 (OmniState)
│       └── prompts.py  # 专家级 Prompt 模板
├── main.py             # 系统统一入口（支持路径自修复）
└── .gitignore          # 安全忽略名单 (含 .env)
```

## 📌 典型使用场景
- 威胁处置流程标准化：将安全专家的分析逻辑固化为可复用的节点
- SOC 运营效率提升：基于AI协助，显著缩短告警从发现到处置的全流程耗时

## 👤 作者
xyl-muse

Cybersecurity Engineer | Aspiring AI Engineer