"""LangGraph 工作流定义：纯工具执行，不包含 LLM"""

import sys
from langgraph.graph import StateGraph, END

from .state import ScannerState
from .config import (
    INJECTION_PAYLOADS, 
    ATTACK_DESCRIPTIONS, 
    OWASP_MCP_CATEGORIES,
    TOOL_DESCRIPTION_RISK_PATTERNS,
    DANGEROUS_TOOL_PATTERNS,
    DANGEROUS_RESOURCE_PATTERNS,
)


# --- 纯函数节点 (不需要 LLM) ---

def analyze_tool_description(name: str, description: str) -> list:
    """分析工具描述中的安全风险"""
    risks = []
    desc_lower = description.lower()
    
    # 检测危险工具名称
    for pattern in DANGEROUS_TOOL_PATTERNS:
        if pattern.lower() in name.lower():
            risks.append({
                "type": "dangerous_tool_name",
                "severity": "HIGH",
                "detail": f"工具名称包含危险模式: {pattern}",
                "evidence": name,
            })
    
    # 检测工具描述中的风险模式
    for risk_type, patterns in TOOL_DESCRIPTION_RISK_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in desc_lower:
                severity = "CRITICAL" if risk_type in ["hidden_instruction", "behavior_hijacking"] else "HIGH"
                risks.append({
                    "type": f"description_{risk_type}",
                    "severity": severity,
                    "detail": f"工具描述包含{risk_type}风险模式: {pattern}",
                    "evidence": pattern,
                })
    
    return risks


async def recon_node(state: ScannerState) -> dict:
    """侦察节点：获取目标工具列表并分析工具描述安全性"""
    from mcp.client.sse import sse_client
    from mcp.client.session import ClientSession
    
    url = state["target_url"]
    headers = state["headers"]
    
    print(f"[Graph:Recon] 侦察目标: {url}", file=sys.stderr)
    
    try:
        async with sse_client(url, headers=headers, timeout=15.0) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()
                
                tools = []
                attack_surface = []
                description_vulnerabilities = []  # 工具描述漏洞
                
                for t in result.tools:
                    tool_info = {
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.inputSchema,
                    }
                    tools.append(tool_info)
                    
                    # 分析工具描述安全性 
                    desc_risks = analyze_tool_description(t.name, t.description or "")
                    for risk in desc_risks:
                        description_vulnerabilities.append({
                            "tool_name": t.name,
                            "attack_type": "mcp_tool_description_injection",
                            "attack_description": ATTACK_DESCRIPTIONS.get("mcp_tool_description_injection", "工具描述注入"),
                            "payload": "N/A (静态分析)",
                            "severity": risk["severity"],
                            "evidence": [risk["evidence"]],
                            "detail": risk["detail"],
                            "risk_type": risk["type"],
                        })
                        print(f"[Graph:Recon] ⚠️ 工具描述风险! {t.name} - {risk['type']} [{risk['severity']}]", file=sys.stderr)
                    
                    # 分析可注入参数
                    string_params = [
                        p for p, info in t.inputSchema.get("properties", {}).items()
                        if info.get("type") == "string"
                    ]
                    
                    if string_params:
                        attack_surface.append({
                            "tool_name": t.name,
                            "injectable_params": string_params,
                            "schema": t.inputSchema,
                        })
                
                # 尝试获取资源列表
                resources = []
                resource_vulnerabilities = []
                try:
                    resources_result = await session.list_resources()
                    for r in resources_result.resources:
                        resources.append({
                            "uri": str(r.uri),
                            "name": r.name,
                            "description": getattr(r, "description", ""),
                        })
                        
                        # 检测危险资源
                        uri_str = str(r.uri).lower()
                        for pattern in DANGEROUS_RESOURCE_PATTERNS:
                            if pattern.lower() in uri_str:
                                resource_vulnerabilities.append({
                                    "tool_name": f"resource:{r.name}",
                                    "attack_type": "mcp_resource_injection",
                                    "attack_description": ATTACK_DESCRIPTIONS.get("mcp_resource_injection", "危险资源"),
                                    "payload": str(r.uri),
                                    "severity": "HIGH",
                                    "evidence": [pattern],
                                    "detail": f"发现危险资源URI: {r.uri}",
                                })
                                print(f"[Graph:Recon] ⚠️ 危险资源! {r.uri} [{pattern}]", file=sys.stderr)
                except Exception:
                    pass  # 资源列表可能不可用
                
                print(f"[Graph:Recon] 发现 {len(tools)} 个工具, {len(resources)} 个资源", file=sys.stderr)
                print(f"[Graph:Recon] 工具描述漏洞: {len(description_vulnerabilities)}, 资源漏洞: {len(resource_vulnerabilities)}", file=sys.stderr)
                
                return {
                    "discovered_tools": tools,
                    "attack_surface": attack_surface,
                    "vulnerabilities": description_vulnerabilities + resource_vulnerabilities,
                    "resources": resources,
                }
                
    except Exception as e:
        return {"error": f"侦察失败: {str(e)}"}


async def plan_node(state: ScannerState) -> dict:
    """规划节点：生成攻击队列"""
    attack_surface = state.get("attack_surface", [])
    
    pending_attacks = []
    for target in attack_surface:
        for attack_type, payloads in INJECTION_PAYLOADS.items():
            for payload in payloads[:2]:  # 每种类型取前2个
                pending_attacks.append({
                    "tool_name": target["tool_name"],
                    "attack_type": attack_type,
                    "payload": payload,
                    "schema": target["schema"],
                })
    
    print(f"[Graph:Plan] 生成 {len(pending_attacks)} 个攻击任务", file=sys.stderr)
    
    return {"pending_attacks": pending_attacks}


async def attack_node(state: ScannerState) -> dict:
    """攻击节点：执行所有攻击"""
    from mcp.client.sse import sse_client
    from mcp.client.session import ClientSession
    from .config import SENSITIVE_PATTERNS
    
    url = state["target_url"]
    headers = state["headers"]
    pending_attacks = state.get("pending_attacks", [])
    
    attack_results = []
    # 继承侦察阶段发现的漏洞
    vulnerabilities = list(state.get("vulnerabilities", []))
    
    print(f"[Graph:Attack] 执行 {len(pending_attacks)} 个攻击", file=sys.stderr)
    
    try:
        async with sse_client(url, headers=headers, timeout=120.0) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                
                for attack in pending_attacks:
                    tool_name = attack["tool_name"]
                    attack_type = attack["attack_type"]
                    payload = attack["payload"]
                    schema = attack["schema"]
                    
                    # 构造参数
                    test_args = {}
                    for param_name, param_info in schema.get("properties", {}).items():
                        param_type = param_info.get("type", "string")
                        if param_type == "string":
                            test_args[param_name] = payload
                        elif param_type == "integer":
                            test_args[param_name] = 1
                        elif param_type == "number":
                            test_args[param_name] = 1.0
                        elif param_type == "boolean":
                            test_args[param_name] = True
                    
                    try:
                        result = await session.call_tool(tool_name, test_args)
                        response_text = ""
                        for content in result.content:
                            response_text += getattr(content, "text", str(content))
                        
                        # 检测漏洞
                        is_vulnerable = False
                        detected = []
                        for pattern in SENSITIVE_PATTERNS:
                            if pattern.lower() in response_text.lower():
                                is_vulnerable = True
                                detected.append(pattern)
                        
                        attack_result = {
                            "tool_name": tool_name,
                            "attack_type": attack_type,
                            "payload": payload,
                            "actual_args": test_args,
                            "response_preview": response_text[:300],
                            "is_vulnerable": is_vulnerable,
                            "detected_patterns": detected,
                        }
                        attack_results.append(attack_result)
                        
                        if is_vulnerable:
                            # 根据检测到的模式判断严重程度
                            critical_patterns = [
                                "root:", "/etc/passwd", "/etc/shadow",
                                "AWS_ACCESS_KEY", "private_key", "BEGIN RSA PRIVATE",
                                "169.254.169.254", "iam/security-credentials",
                            ]
                            high_patterns = [
                                "password", "api_key", "apikey", "secret",
                                "token", "credential", "mongodb://", "mysql://",
                                "whoami", "uid=", "PWNED",
                            ]
                            
                            detected_lower = [d.lower() for d in detected]
                            if any(p.lower() in detected_lower for p in critical_patterns):
                                severity = "CRITICAL"
                            elif any(p.lower() in detected_lower for p in high_patterns):
                                severity = "HIGH"
                            else:
                                severity = "MEDIUM"
                            
                            vulnerabilities.append({
                                "tool_name": tool_name,
                                "attack_type": attack_type,
                                "attack_description": ATTACK_DESCRIPTIONS.get(attack_type, attack_type),
                                "payload": payload,
                                "severity": severity,
                                "evidence": detected,
                            })
                            print(f"[Graph:Attack] ⚠️ 漏洞! {tool_name} - {attack_type} [{severity}]", file=sys.stderr)
                            
                    except Exception as e:
                        attack_results.append({
                            "tool_name": tool_name,
                            "attack_type": attack_type,
                            "payload": payload,
                            "error": str(e),
                        })
                        
    except Exception as e:
        return {"error": f"攻击失败: {str(e)}", "attack_results": attack_results, "vulnerabilities": vulnerabilities}
    
    print(f"[Graph:Attack] 完成，发现 {len(vulnerabilities)} 个漏洞", file=sys.stderr)
    
    return {"attack_results": attack_results, "vulnerabilities": vulnerabilities}


def report_node(state: ScannerState) -> dict:
    """报告节点：生成最终报告"""
    vulnerabilities = state.get("vulnerabilities", [])
    attack_results = state.get("attack_results", [])
    discovered_tools = state.get("discovered_tools", [])
    
    vuln_count = len(vulnerabilities)
    if vuln_count == 0:
        risk_level = "LOW"
    elif vuln_count <= 2:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"
    
    return {
        "next_action": "finish",
    }


# --- 构建工作流 ---
def build_scanner_graph():
    """构建扫描工作流（无 LLM，纯执行）"""
    workflow = StateGraph(ScannerState)
    
    workflow.add_node("recon", recon_node)
    workflow.add_node("plan", plan_node)
    workflow.add_node("attack", attack_node)
    workflow.add_node("report", report_node)
    
    workflow.set_entry_point("recon")
    workflow.add_edge("recon", "plan")
    workflow.add_edge("plan", "attack")
    workflow.add_edge("attack", "report")
    workflow.add_edge("report", END)
    
    return workflow.compile()


async def run_graph_scan(url: str, token: str = "") -> dict:
    """执行扫描"""
    print(f"[Graph] 启动扫描: {url}", file=sys.stderr)
    
    headers = {}
    if token:
        headers["Authorization"] = token if token.lower().startswith(("bearer ", "basic ")) else f"Bearer {token}"
    
    initial_state: ScannerState = {
        "messages": [],
        "target_url": url,
        "target_token": token,
        "headers": headers,
        "discovered_tools": [],
        "attack_surface": [],
        "current_tool": "",
        "current_attack_type": "",
        "pending_attacks": [],
        "attack_results": [],
        "vulnerabilities": [],
        "next_action": "continue",
        "error": "",
    }
    
    graph = build_scanner_graph()
    final_state = await graph.ainvoke(initial_state)
    
    # 生成报告
    vulnerabilities = final_state.get("vulnerabilities", [])
    attack_results = final_state.get("attack_results", [])
    vuln_count = len(vulnerabilities)
    
    # 统计各类攻击结果
    attack_stats = {}
    for result in attack_results:
        atype = result.get("attack_type", "unknown")
        if atype not in attack_stats:
            attack_stats[atype] = {"total": 0, "vulnerable": 0}
        attack_stats[atype]["total"] += 1
        if result.get("is_vulnerable"):
            attack_stats[atype]["vulnerable"] += 1
    
    # 按 MCP 安全分类统计
    mcp_security_summary = {
        "Tool_Description_Injection": 0,  # 工具描述注入
        "Command_Injection": 0,           # 命令注入
        "Code_Execution": 0,              # 代码执行
        "SSRF": 0,                        # 服务端请求伪造
        "Path_Traversal": 0,              # 路径遍历
        "SQL_Injection": 0,               # SQL注入
        "Info_Disclosure": 0,             # 信息泄露
        "Resource_Injection": 0,          # 资源注入
    }
    
    for vuln in vulnerabilities:
        atype = vuln.get("attack_type", "")
        
        # 使用 MCP 安全分类映射
        categorized = False
        for category, attack_types in OWASP_MCP_CATEGORIES.items():
            if atype in attack_types:
                if category in mcp_security_summary:
                    mcp_security_summary[category] += 1
                categorized = True
                break
        
        # 未分类的归入 Info_Disclosure
        if not categorized and vuln.get("is_vulnerable", True):
            mcp_security_summary["Info_Disclosure"] += 1
    
    report = {
        "target": url,
        "risk_level": "LOW" if vuln_count == 0 else ("MEDIUM" if vuln_count <= 2 else ("HIGH" if vuln_count <= 5 else "CRITICAL")),
        "summary": {
            "tools_discovered": len(final_state.get("discovered_tools", [])),
            "attacks_executed": len(attack_results),
            "vulnerabilities_found": vuln_count,
        },
        "mcp_security_summary": mcp_security_summary,
        "attack_statistics": attack_stats,
        "vulnerabilities": vulnerabilities,
        "tools": final_state.get("discovered_tools", []),
        "attack_details": attack_results,
        "error": final_state.get("error"),
    }
    
    print(f"[Graph] 完成! 风险: {report['risk_level']}", file=sys.stderr)
    
    return report
