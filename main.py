"""
Security Scanner - MCP 安全扫描服务
使用 LangGraph ReAct 多智能体架构

目录结构:
├── main.py                    # 入口文件
├── security_scanner/
│   ├── __init__.py           # 包初始化
│   ├── config.py             # 配置：攻击载荷、敏感模式
│   ├── state.py              # 状态定义
│   ├── tools.py              # 工具定义 (供 ToolNode 使用)
│   ├── agents.py             # 智能体定义 (ReAct)
│   ├── graph.py              # LangGraph 工作流
│   └── server.py             # MCP 服务器
"""

from security_scanner.server import run_server

if __name__ == "__main__":
    run_server(host="0.0.0.0", port=8000)
