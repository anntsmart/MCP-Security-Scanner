"""MCP 服务器：异步任务模式的安全扫描服务

工作流程：
1. start_scan(url, token) -> 返回 task_id（立即返回）
2. get_scan_status(task_id) -> 返回进度和状态
3. get_scan_result(task_id) -> 返回最终结果
"""

import sys
import json
from fastmcp import FastMCP
from .task_manager import task_manager, TaskStatus
from .agent import SecurityAgent

mcp = FastMCP("Security-Scanner")


def _clean_token(token: str) -> str:
    """清理和格式化 Token"""
    if not token:
        return ""
    clean_token = token.strip()
    if "Authorization=" in clean_token:
        clean_token = clean_token.split("Authorization=")[1].strip()
    if not clean_token.lower().startswith(("bearer ", "basic ")):
        clean_token = f"Bearer {clean_token}"
    return clean_token


def _format_vulnerability_detail(vuln: dict) -> dict:
    """格式化漏洞详情，生成详细的 POC 报告"""
    attack_type = vuln.get("attack_type", "")
    tool_name = vuln.get("tool_name", "")
    payload = vuln.get("payload", "")
    severity = vuln.get("severity", "MEDIUM")
    detected_patterns = vuln.get("detected_patterns", [])
    response_preview = vuln.get("response_preview", "")
    response_length = vuln.get("response_length", 0)
    details = vuln.get("details", {})
    
    # 基础信息
    result = {
        "severity": severity,
        "tool": tool_name,
        "type": attack_type,
        "type_cn": _get_attack_type_cn(attack_type),
    }
    
    # POC 详情
    poc = {
        "tool_name": tool_name,
        "payload": payload,
        "description": "",
        "evidence": detected_patterns,  # 默认证据
    }
    
    # 根据攻击类型生成详细描述和证据
    if attack_type == "mcp_excessive_data_exposure":
        excessive = details.get("excessive_data", {})
        record_count = excessive.get("record_count", 0)
        poc["description"] = f"使用空查询或通配符查询，系统返回了 {record_count:,} 条记录"
        poc["risk_description"] = "普通用户不应能够获取如此大量的数据，存在数据泄露风险"
        poc["recommendation"] = "1. 实施分页限制，单次查询最多返回100条\n2. 添加权限校验，限制用户可查询的数据范围\n3. 对敏感查询添加审计日志"
        poc["record_count"] = record_count
        poc["response_size"] = f"{response_length // 1024}KB" if response_length > 1024 else f"{response_length}B"
        
    elif attack_type == "mcp_sensitive_business_probe":
        sensitive = details.get("sensitive_business", {})
        categories = sensitive.get("categories", [])
        evidence = sensitive.get("evidence", [])
        category_cn = {
            "hr_data": "HR人事数据",
            "finance_data": "财务数据", 
            "pii_data": "个人隐私数据(PII)",
            "org_data": "组织架构数据"
        }
        categories_cn = [category_cn.get(c, c) for c in categories]
        poc["description"] = f"查询返回了敏感业务数据"
        poc["sensitive_categories"] = categories_cn
        poc["evidence"] = evidence[:5]
        poc["risk_description"] = "敏感数据未经脱敏直接返回，可能违反数据保护法规"
        poc["recommendation"] = "1. 对敏感字段进行脱敏处理\n2. 实施基于角色的访问控制(RBAC)\n3. 记录敏感数据访问日志"
        
    elif attack_type == "mcp_idor":
        idor = details.get("idor", {})
        poc["description"] = f"使用测试ID '{payload}' 成功获取到其他用户的数据"
        poc["evidence"] = idor.get("evidence", detected_patterns)
        poc["risk_description"] = "存在越权访问漏洞，攻击者可遍历ID获取任意用户数据"
        poc["recommendation"] = "1. 验证当前用户是否有权访问请求的资源\n2. 使用不可预测的资源标识符(如UUID)\n3. 实施访问控制列表(ACL)"
        
    elif attack_type in ["hardcoded_credential", "static_analysis"]:
        poc["description"] = f"工具 '{tool_name}' 定义中发现硬编码的认证凭据"
        poc["evidence"] = detected_patterns
        poc["param_name"] = payload
        poc["risk_description"] = "硬编码凭据可能被攻击者利用，获取未授权访问"
        poc["recommendation"] = "1. 移除硬编码凭据\n2. 使用环境变量或密钥管理服务\n3. 定期轮换凭据"
        
    else:
        poc["description"] = f"使用载荷 '{payload[:50] if payload else 'N/A'}' 进行测试"
        poc["evidence"] = detected_patterns
        poc["risk_description"] = "检测到潜在安全风险"
        poc["recommendation"] = "请根据具体情况进行安全加固"
    
    # 所有漏洞都添加响应证据（用于验证漏洞真实性）
    if response_preview:
        result["response_evidence"] = response_preview[:1000]  # 最多显示1000字符
    elif detected_patterns:
        # 如果没有响应预览，用检测到的模式作为证据
        result["response_evidence"] = "\n".join(str(p) for p in detected_patterns[:5])
    
    if response_length > 0:
        result["response_length"] = response_length
    
    result["poc"] = poc
    return result


def _get_attack_type_cn(attack_type: str) -> str:
    """获取攻击类型的中文名称"""
    type_map = {
        "mcp_excessive_data_exposure": "过度数据暴露",
        "mcp_sensitive_business_probe": "敏感业务数据泄露",
        "mcp_idor": "越权访问(IDOR)",
        "mcp_command_injection": "命令注入",
        "mcp_sql_injection": "SQL注入",
        "mcp_ssrf": "服务端请求伪造(SSRF)",
        "mcp_path_traversal": "路径遍历",
        "hardcoded_credential": "硬编码凭据",
        "description_injection": "工具描述注入",
    }
    return type_map.get(attack_type, attack_type)


def _summarize_response(response: str, max_length: int = 200) -> str:
    """总结响应内容"""
    if not response:
        return "无响应内容"
    
    if len(response) <= max_length:
        return response
    
    # 尝试提取关键信息
    import re
    
    # 提取 JSON 中的关键字段
    summary_parts = []
    
    # 提取记录数
    count_match = re.search(r'"(?:total|count|totalElements)"\s*:\s*(\d+)', response, re.IGNORECASE)
    if count_match:
        summary_parts.append(f"记录数: {int(count_match.group(1)):,}")
    
    # 提取字段名
    field_match = re.findall(r'"([a-zA-Z_\u4e00-\u9fa5]+)":', response[:500])
    if field_match:
        unique_fields = list(dict.fromkeys(field_match))[:10]
        summary_parts.append(f"包含字段: {', '.join(unique_fields)}")
    
    if summary_parts:
        return " | ".join(summary_parts) + f" | 响应长度: {len(response)} 字符"
    
    return response[:max_length] + f"... (共 {len(response)} 字符)"


@mcp.tool()
async def start_scan(url: str, token: str = "", llm_provider: str = "qwen", mode: str = "fast") -> dict:
    """
    启动 MCP 安全扫描任务（异步模式）。
    
    该工具会立即返回任务ID，扫描在后台执行。
    使用 get_scan_status 查询进度，使用 get_scan_result 获取结果。
    
    Args:
        url: 目标 MCP SSE 服务器 URL
        token: 认证 Token（Bearer 格式）
        llm_provider: LLM 提供商 (qwen/azure)
        mode: 扫描模式 - "fast"(快速并发扫描) 或 "full"(完整LLM引导扫描)
    
    Returns:
        task_id: 任务ID，用于查询状态和结果
    """
    token = _clean_token(token)
    print(f"[MCP] 创建扫描任务: {url} (模式: {mode})", file=sys.stderr)
    
    # 创建任务
    task = task_manager.create_task(url, token)
    
    # 根据模式选择扫描函数
    if mode == "fast":
        async def run_scan(task):
            agent = SecurityAgent(llm_provider=llm_provider)
            return await agent.fast_scan(task)
    else:
        async def run_scan(task):
            agent = SecurityAgent(llm_provider=llm_provider)
            return await agent.scan(task)
    
    # 启动后台任务
    await task_manager.start_task(task, run_scan)
    
    mode_desc = "快速并发扫描" if mode == "fast" else "完整LLM引导扫描"
    return {
        "status": "started",
        "task_id": task.task_id,
        "mode": mode,
        "message": f"扫描任务已启动（{mode_desc}），请使用 get_scan_status('{task.task_id}') 查询进度"
    }


@mcp.tool()
async def get_scan_status(task_id: str) -> dict:
    """
    查询扫描任务的状态和进度。
    
    Args:
        task_id: 任务ID（由 start_scan 返回）
    
    Returns:
        status: 任务状态 (pending/running/completed/failed)
        progress: 进度百分比 (0-100)
        current_step: 当前执行步骤
        logs: 最近的执行日志
        next_action: 建议的下一步操作
    """
    task = task_manager.get_task(task_id)
    
    if not task:
        return {
            "status": "error",
            "error": f"任务不存在: {task_id}"
        }
    
    # 根据状态给出明确的下一步指示
    if task.status == TaskStatus.COMPLETED:
        return {
            "status": "completed",
            "progress": 100,
            "message": "✅ 扫描已完成！请立即调用 get_scan_result 获取完整报告。",
            "next_action": f"get_scan_result(task_id='{task_id}')",
            "logs": task.logs[-5:]
        }
    
    if task.status == TaskStatus.FAILED:
        return {
            "status": "failed",
            "error": task.error,
            "message": "❌ 扫描失败",
            "logs": task.logs[-10:]
        }
    
    if task.status == TaskStatus.PENDING:
        return {
            "status": "pending",
            "progress": 0,
            "message": "⏳ 任务等待中...",
            "next_action": "请稍后再次查询状态"
        }
    
    # running - 返回详细的阶段性数据
    result = {
        "status": "running",
        "progress": task.progress,
        "current_phase": task.current_phase,
        "current_step": task.current_step,
        "message": f"🔄 扫描进行中 ({task.progress}%) - {task.current_phase}",
        "next_action": "请等待几秒后再次查询状态",
        "logs": task.logs[-3:]
    }
    
    # 如果侦察阶段已完成，返回侦察数据
    if task.recon_data:
        result["recon_summary"] = {
            "tools_count": task.recon_data["tools_count"],
            "injectable_count": task.recon_data["injectable_count"],
            "tools": [t["name"] for t in task.recon_data["tools"]],
            "attack_surface": [
                f"{s['tool_name']} ({len(s['injectable_params'])} 个可注入参数: {', '.join(s['injectable_params'][:3])})"
                for s in task.recon_data["attack_surface"][:5]  # 最多显示5个
            ]
        }
    
    # 返回攻击进度
    if task.attack_progress["completed_attacks"] > 0:
        result["attack_progress"] = {
            "completed_attacks": task.attack_progress["completed_attacks"],
            "vulnerabilities_found": task.attack_progress["vulnerabilities_found"]
        }
    
    return result


@mcp.tool()
async def get_scan_result(task_id: str) -> dict:
    """
    获取扫描任务的最终结果。
    
    只有当任务状态为 completed 或 failed 时才有结果。
    
    Args:
        task_id: 任务ID（由 start_scan 返回）
    
    Returns:
        完整的扫描报告，包括发现的漏洞、风险等级等
    """
    task = task_manager.get_task(task_id)
    
    if not task:
        return {
            "status": "error",
            "error": f"任务不存在: {task_id}"
        }
    
    if task.status == TaskStatus.PENDING:
        return {
            "status": "pending",
            "message": "任务尚未开始"
        }
    
    if task.status == TaskStatus.RUNNING:
        return {
            "status": "running",
            "progress": task.progress,
            "current_step": task.current_step,
            "message": "任务正在执行中，请稍后再查询"
        }
    
    if task.status == TaskStatus.FAILED:
        return {
            "status": "failed",
            "error": task.error,
            "logs": task.logs
        }
    
    # completed - 返回格式化的报告
    result = task.result or {}
    
    # 构建易读的报告
    report = {
        "status": "completed",
        "message": "✅ 扫描完成！以下是完整的安全报告：",
        "target": result.get("target", task.url),
        "risk_level": result.get("risk_level", "UNKNOWN"),
        "summary": result.get("summary", {}),
    }
    
    # 添加漏洞详情 - 按严重程度分组并排序
    vulnerabilities = result.get("vulnerabilities", [])
    if vulnerabilities:
        # 分组统计
        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        by_type = {}  # 按漏洞类型统计
        affected_tools = set()
        
        for v in vulnerabilities:
            sev = v.get("severity", "MEDIUM")
            attack_type = v.get("attack_type", "unknown")
            tool_name = v.get("tool_name", "")
            
            if sev in by_severity:
                by_severity[sev].append(_format_vulnerability_detail(v))
            
            # 按类型统计
            if attack_type not in by_type:
                by_type[attack_type] = []
            by_type[attack_type].append(tool_name)
            affected_tools.add(tool_name)
        
        report["vulnerability_count"] = len(vulnerabilities)
        report["severity_breakdown"] = result.get("severity_breakdown", {})
        report["vulnerabilities_by_severity"] = {}
        
        # 按严重程度输出详情
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if by_severity[sev]:
                report["vulnerabilities_by_severity"][sev] = {
                    "count": len(by_severity[sev]),
                    "details": by_severity[sev]
                }
        
        # 添加修复优先级建议
        report["remediation_priority"] = []
        priority_order = 1
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if by_severity[sev]:
                for vuln in by_severity[sev]:
                    report["remediation_priority"].append({
                        "priority": priority_order,
                        "severity": sev,
                        "tool": vuln.get("tool", ""),
                        "type": vuln.get("type_cn", vuln.get("type", "")),
                        "action": vuln.get("poc", {}).get("recommendation", "请进行安全加固")[:100]
                    })
                    priority_order += 1
        
        # 添加影响范围摘要
        report["impact_summary"] = {
            "affected_tools": list(affected_tools),
            "affected_tools_count": len(affected_tools),
            "vulnerability_types": list(by_type.keys()),
        }
    else:
        report["vulnerability_count"] = 0
        report["message"] = "✅ 扫描完成，未发现安全漏洞"
    
    # 添加工具列表
    tools = result.get("tools", [])
    if tools:
        report["discovered_tools"] = [t.get("name", "") for t in tools]
    
    return report


@mcp.tool()
async def list_scan_tasks() -> dict:
    """
    列出所有扫描任务。
    
    Returns:
        所有任务的列表，包括状态和基本信息
    """
    tasks = task_manager.list_tasks()
    return {
        "status": "success",
        "count": len(tasks),
        "tasks": tasks
    }


@mcp.tool()
async def clear_scan_tasks(task_id: str = "") -> dict:
    """
    清除扫描任务。
    
    Args:
        task_id: 要清除的任务ID，如果为空则清除所有任务
    
    Returns:
        清除结果
    """
    if task_id:
        success = task_manager.clear_task(task_id)
        return {
            "status": "success" if success else "error",
            "message": f"任务 {task_id} 已清除" if success else f"任务 {task_id} 不存在"
        }
    else:
        task_manager.clear_all_tasks()
        return {
            "status": "success",
            "message": "所有任务已清除"
        }


def run_server(host: str = "0.0.0.0", port: int = 8000):
    """启动 MCP 服务器"""
    print(f"启动 Security Scanner MCP: http://{host}:{port}/sse")
    print("可用工具:")
    print("  - start_scan(url, token) -> 启动扫描，返回 task_id")
    print("  - get_scan_status(task_id) -> 查询进度")
    print("  - get_scan_result(task_id) -> 获取结果")
    print("  - list_scan_tasks() -> 列出所有任务")
    mcp.run(transport="sse", host=host, port=port)
