# MCP Security Scanner

一个基于 LangGraph ReAct 架构的 MCP (Model Context Protocol) 安全扫描工具，用于自动化检测 MCP 服务的安全漏洞。

## 功能特性

- **自动化安全扫描**：自动发现 MCP 服务暴露的工具并进行安全测试
- **多种攻击检测**：
  - 命令注入 (Command Injection)
  - 代码执行 (Code Execution)
  - SQL 注入 (SQL Injection)
  - SSRF (Server-Side Request Forgery)
  - 路径遍历 (Path Traversal)
  - 越权访问 (IDOR)
  - 过度数据暴露 (Excessive Data Exposure)
  - 敏感业务数据泄露
  - 硬编码凭据检测
  - 工具描述注入
- **智能 Payload 生成**：根据工具类型和参数自动生成针对性测试载荷
- **异步任务管理**：支持后台扫描，实时查询进度
- **双模式扫描**：
  - `fast` 模式：快速并发扫描
  - `full` 模式：完整 LLM 引导扫描
- **详细报告**：生成包含 POC 和修复建议的安全报告

## 安装

```bash
pip install -r requirements.txt
推荐使用uv环境
uv init MCP  
cd MCP
echo "3.13" > .python-version
uv venv
source .venv/bin/activate
uv add "mcp[cli]" httpx
```
### 依赖

- Python 3.10+
- langgraph
- fastmcp
- httpx
- mcp

## 快速开始

### 启动 MCP 服务器

```bash
python main.py
```
使用uv安装：uv run main.py
服务器默认运行在 `http://0.0.0.0:8000/sse`

### 使用方式

通过 MCP 客户端（如 Cherry Studio/Kiro/Cursor/Trae）连接：
{
  "mcpServers": {
    "Security-Scanner": {
      "url": "http://10.0.xx.xx:8000/sse"
    }
  }
}

#### 1. 启动扫描

无Token:
对该MCP进行安全扫描
http://xxx.xxx.xxx:7777/sse
<img width="866" height="405" alt="image" src="https://github.com/user-attachments/assets/a442e603-6f1b-44af-8f58-e3b91f77db80" />

有Token:
对该MCP进行安全扫描
https://xxx.xxx.xxx/mcp-servers/plant-monitor-getproductionorder/sse
Authorization=Bearer apikey-693xxxxxxxxxxxxx
<img width="844" height="525" alt="image" src="https://github.com/user-attachments/assets/34cf3d8b-4860-41e6-8da2-b4c34d606d74" />

#### 2. 查询进度

输入“继续”：
<img width="831" height="769" alt="image" src="https://github.com/user-attachments/assets/342af922-3aca-42fa-b44f-6d360915c098" />


#### 3. 获取结果

输入“获取扫描详情”：
<img width="817" height="590" alt="image" src="https://github.com/user-attachments/assets/d836d428-5e57-4adf-bd4d-d19f9a0fc0a9" />




## 项目结构

```
├── agent.py          # ReAct 智能体实现
├── config.py         # 攻击载荷和检测规则配置
├── graph.py          # LangGraph 工作流定义
├── llm.py            # LLM 客户端（支持通义千问/Azure OpenAI）
├── server.py         # FastMCP 服务器
├── state.py          # 状态定义
├── task_manager.py   # 异步任务管理器
├── tools.py          # 安全检测工具函数
└── system_prompt.md  # 系统提示词
```

## 配置

### LLM 配置

在 `llm.py` 中配置 LLM 提供商：

- **通义千问** (默认)
- **Azure OpenAI**

### 攻击载荷

在 `config.py` 中自定义：

- `MCP_INJECTION_PAYLOADS`：各类攻击载荷
- `SENSITIVE_PATTERNS`：敏感信息检测模式
- `TOOL_TYPE_PATTERNS`：工具类型识别规则

## 检测能力

| 漏洞类型 | 严重程度 | 说明 |
|---------|---------|------|
| 命令注入 | CRITICAL | 检测系统命令执行 |
| 代码执行 | CRITICAL | 检测任意代码执行 |
| SQL 注入 | HIGH | 检测数据库注入 |
| SSRF | HIGH | 检测内网资源访问 |
| 路径遍历 | HIGH | 检测文件系统访问 |
| IDOR | HIGH | 检测越权访问 |
| 数据暴露 | MEDIUM | 检测大量数据返回 |
| 敏感数据 | HIGH/CRITICAL | 检测 PII/HR/财务数据 |
| 硬编码凭据 | HIGH | 检测 Schema 中的凭据 |

## 输出示例

```json
{
  "status": "completed",
  "target": "http://example.com/sse",
  "risk_level": "HIGH",
  "summary": {
    "tools_discovered": 10,
    "injectable_tools": 5,
    "attacks_executed": 30,
    "vulnerabilities_found": 3
  },
  "vulnerabilities_by_severity": {
    "HIGH": {
      "count": 2,
      "details": [...]
    },
    "MEDIUM": {
      "count": 1,
      "details": [...]
    }
  }
}
```

## 许可证

MIT License

## 免责声明

本工具仅用于授权的安全测试。请勿用于未经授权的系统。使用者需自行承担使用本工具的所有风险和责任。
