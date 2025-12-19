"""工具定义"""

import sys
import re
import json
from typing import List, Dict
from mcp.client.sse import sse_client
from mcp.client.session import ClientSession

from .config import (
    INJECTION_PAYLOADS, 
    SENSITIVE_PATTERNS,
    SENSITIVE_PATTERNS_HIGH_CONFIDENCE,
    SENSITIVE_PATTERNS_MEDIUM_CONFIDENCE,
    HARDCODED_CREDENTIAL_PATTERNS,
    SENSITIVE_PARAM_NAMES,
    TOOL_DESCRIPTION_RISK_PATTERNS,
    SENSITIVE_BUSINESS_PATTERNS,
    TOOL_TYPE_PATTERNS,
    PARAM_TYPE_PAYLOADS,
    ATTACK_TYPE_SEVERITY,
)


def _detect_hardcoded_credentials(tool_name: str, schema: dict) -> list:
    """检测工具 schema 中的硬编码凭据"""
    vulnerabilities = []
    properties = schema.get("properties", {})
    
    for param_name, param_info in properties.items():
        param_lower = param_name.lower()
        default_value = param_info.get("default", "")
        
        if not default_value or not isinstance(default_value, str):
            continue
        
        is_sensitive_param = any(s in param_lower for s in SENSITIVE_PARAM_NAMES)
        found_vuln = False
        
        # 1. 检查 Authorization 头
        for pattern in HARDCODED_CREDENTIAL_PATTERNS.get("authorization_header", []):
            if pattern in default_value:
                vulnerabilities.append({
                    "type": "hardcoded_credential",
                    "tool_name": tool_name,
                    "param_name": param_name,
                    "severity": "HIGH",
                    "evidence": f"发现硬编码的 {pattern.strip()} 认证: {default_value[:50]}...",
                    "recommendation": "不应在工具定义中硬编码认证凭据"
                })
                found_vuln = True
                break
        
        if found_vuln:
            continue

        # 2. 检查 UUID 格式的 Token/Key
        uuid_pattern = r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
        if is_sensitive_param and re.match(uuid_pattern, default_value, re.IGNORECASE):
            vulnerabilities.append({
                "type": "hardcoded_credential",
                "tool_name": tool_name,
                "param_name": param_name,
                "severity": "HIGH",
                "evidence": f"发现硬编码的 UUID 格式凭据 ({param_name}): {default_value}",
                "recommendation": "不应在工具定义中硬编码 API Key 或 Token"
            })
            continue
        
        # 3. 检查长字符串格式的 Key（16位以上）
        if is_sensitive_param and len(default_value) >= 16:
            if re.match(r'^[a-zA-Z0-9_\-]{16,}$', default_value):
                vulnerabilities.append({
                    "type": "hardcoded_credential",
                    "tool_name": tool_name,
                    "param_name": param_name,
                    "severity": "HIGH",
                    "evidence": f"发现硬编码的凭据 ({param_name}): {default_value[:30]}...",
                    "recommendation": "不应在工具定义中硬编码凭据"
                })
                continue
        
        # 4. 检查 Base64 编码的凭据
        if is_sensitive_param and len(default_value) > 20:
            if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', default_value):
                vulnerabilities.append({
                    "type": "hardcoded_credential",
                    "tool_name": tool_name,
                    "param_name": param_name,
                    "severity": "HIGH",
                    "evidence": f"发现疑似 Base64 编码的硬编码凭据: {default_value[:30]}...",
                    "recommendation": "不应在工具定义中硬编码凭据"
                })
                continue
        
        # 5. 敏感参数名 + 任意非空默认值（兜底检测）
        if is_sensitive_param and len(default_value) >= 1:
            placeholder_patterns = ["xxx", "your_", "example", "test", "demo", "<", ">", "{", "}", "placeholder", "null", "none"]
            is_placeholder = any(p in default_value.lower() for p in placeholder_patterns)
            
            if not is_placeholder:
                severity = "MEDIUM" if len(default_value) >= 8 else "LOW"
                vulnerabilities.append({
                    "type": "hardcoded_credential",
                    "tool_name": tool_name,
                    "param_name": param_name,
                    "severity": severity,
                    "evidence": f"敏感参数 '{param_name}' 存在硬编码默认值: {default_value[:50]}",
                    "recommendation": "敏感参数不应设置默认值，应由用户在运行时提供"
                })
    
    return vulnerabilities


def identify_tool_type(tool_name: str, description: str, params: list) -> dict:
    """识别工具类型，返回推荐的攻击策略"""
    tool_name_lower = tool_name.lower()
    desc_lower = (description or "").lower()
    
    matched_types = []
    
    for type_name, type_config in TOOL_TYPE_PATTERNS.items():
        if type_name == "default":
            continue
        
        score = 0
        # 检查工具名称
        for pattern in type_config["name_patterns"]:
            if pattern.lower() in tool_name_lower:
                score += 2
                break
        
        # 检查描述
        for pattern in type_config["desc_patterns"]:
            if pattern.lower() in desc_lower:
                score += 1
                break
        
        if score > 0:
            matched_types.append((type_name, score, type_config))
    
    # 按分数排序，取最高分的类型
    if matched_types:
        matched_types.sort(key=lambda x: x[1], reverse=True)
        best_match = matched_types[0]
        return {
            "tool_type": best_match[0],
            "confidence": best_match[1],
            "recommended_attacks": best_match[2]["recommended_attacks"],
            "priority_payloads": best_match[2]["priority_payloads"],
        }
    
    # 默认类型
    return {
        "tool_type": "default",
        "confidence": 0,
        "recommended_attacks": TOOL_TYPE_PATTERNS["default"]["recommended_attacks"],
        "priority_payloads": TOOL_TYPE_PATTERNS["default"]["priority_payloads"],
    }


def generate_smart_payloads(tool_name: str, description: str, schema: dict) -> list:
    """基于工具类型和参数智能生成 payload 列表"""
    params = list(schema.get("properties", {}).keys())
    tool_type_info = identify_tool_type(tool_name, description, params)
    
    attack_plans = []
    
    # 1. 基于工具类型的推荐攻击
    for attack_type in tool_type_info["recommended_attacks"]:
        payloads = tool_type_info["priority_payloads"].get(attack_type, [])
        if payloads:
            attack_plans.append({
                "attack_type": attack_type,
                "payloads": payloads[:3],  # 每种攻击最多3个payload
                "source": "tool_type",
                "priority": "high",
            })
    
    # 2. 基于参数类型的针对性攻击
    properties = schema.get("properties", {})
    for param_name, param_info in properties.items():
        param_lower = param_name.lower()
        
        for param_type, param_config in PARAM_TYPE_PAYLOADS.items():
            for pattern in param_config["patterns"]:
                if pattern.lower() in param_lower:
                    attack_plans.append({
                        "attack_type": param_config["attack_type"],
                        "payloads": param_config["payloads"][:2],
                        "target_param": param_name,
                        "source": "param_type",
                        "priority": "high",
                    })
                    break
    
    # 3. 去重并合并
    seen = set()
    unique_plans = []
    for plan in attack_plans:
        key = (plan["attack_type"], tuple(plan["payloads"]))
        if key not in seen:
            seen.add(key)
            unique_plans.append(plan)
    
    return unique_plans


def _detect_description_injection(tool_name: str, description: str) -> list:
    """检测工具描述中的恶意注入"""
    vulnerabilities = []
    if not description:
        return vulnerabilities
    
    desc_lower = description.lower()
    for risk_type, patterns in TOOL_DESCRIPTION_RISK_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in desc_lower:
                vulnerabilities.append({
                    "type": "description_injection",
                    "tool_name": tool_name,
                    "risk_type": risk_type,
                    "severity": "CRITICAL" if risk_type in ["hidden_instruction", "behavior_hijacking"] else "HIGH",
                    "evidence": f"工具描述中发现可疑模式 '{pattern}'",
                    "recommendation": "工具描述不应包含隐藏指令或敏感文件访问指示"
                })
                break
    return vulnerabilities


def _is_successful_response(response_text: str) -> bool:
    """判断响应是否为成功的业务响应（非错误）"""
    response_lower = response_text.lower()
    
    # 明确的错误标识
    error_patterns = [
        # HTTP 错误
        r'"status"\s*:\s*(4\d{2}|5\d{2})',
        r'"code"\s*:\s*(4\d{2}|5\d{2})',
        r'"statusCode"\s*:\s*(4\d{2}|5\d{2})',
        # 错误消息
        r'"error"\s*:\s*["\{]',
        r'"errors"\s*:\s*\[',
        r'"message"\s*:\s*"[^"]*error',
        r'"message"\s*:\s*"[^"]*fail',
    ]
    for pattern in error_patterns:
        if re.search(pattern, response_lower):
            return False
    
    # 明确的错误关键词
    error_keywords = [
        'internal server error', 'bad request', 'unauthorized', 'forbidden',
        'not found', 'exception', 'traceback', 'stack trace',
        'error occurred', 'failed to', 'unable to', 'cannot ',
        '服务器错误', '内部错误', '请求失败', '操作失败', '异常'
    ]
    if any(kw in response_lower for kw in error_keywords):
        return False
    
    return True


def _has_actual_data(response_text: str) -> tuple[bool, int]:
    """判断响应是否包含实际数据，返回 (有数据, 记录数)"""
    response_lower = response_text.lower()
    
    # 首先检查记录数字段（优先级最高）
    count_patterns = [
        r'"totalElements"\s*:\s*(\d+)',
        r'"total_count"\s*:\s*(\d+)',
        r'"totalRecords"\s*:\s*(\d+)',
        r'"total"\s*:\s*(\d+)',
        r'"count"\s*:\s*(\d+)',
        r'"recordCount"\s*:\s*(\d+)',
    ]
    
    for pattern in count_patterns:
        match = re.search(pattern, response_text, re.IGNORECASE)
        if match:
            count = int(match.group(1))
            # 明确返回 0 条记录，就是没有数据
            if count == 0:
                return False, 0
            return True, count
    
    # 检查是否是空数据响应（空数组）
    empty_patterns = [
        r'"data"\s*:\s*\[\s*\]',
        r'"items"\s*:\s*\[\s*\]',
        r'"records"\s*:\s*\[\s*\]',
        r'"list"\s*:\s*\[\s*\]',
        r'"result"\s*:\s*\[\s*\]',
        r'"content"\s*:\s*\[\s*\]',
        r'"rows"\s*:\s*\[\s*\]',
        r'"results"\s*:\s*\[\s*\]',
    ]
    for pattern in empty_patterns:
        if re.search(pattern, response_lower):
            return False, 0
    
    # 检查是否有非空数组数据
    non_empty_array = re.search(r'"(?:data|items|records|list|result|content|rows|results)"\s*:\s*\[\s*\{', response_text, re.IGNORECASE)
    if non_empty_array:
        return True, -1  # -1 表示有数据但数量未知
    
    # 响应太短，认为没有实际数据
    if len(response_text) < 50:
        return False, 0
    
    return False, 0


def _detect_excessive_data(response_text: str) -> dict:
    """检测过度数据暴露 - 基于实际数据量判断"""
    result = {"is_excessive": False, "reason": "", "record_count": 0, "response_size": len(response_text)}
    
    # 1. 首先检查是否是成功响应
    if not _is_successful_response(response_text):
        return result
    
    # 2. 检查是否有实际数据
    has_data, record_count = _has_actual_data(response_text)
    result["record_count"] = record_count
    
    if not has_data:
        return result
    
    # 3. 基于实际数据量判断是否过度暴露
    # 响应体过大（超过 100KB 且有实际数据）
    if len(response_text) > 100 * 1024:
        result["is_excessive"] = True
        result["reason"] = f"响应数据过大 ({len(response_text) // 1024}KB)，包含大量数据"
        return result
    
    # 记录数过多
    if record_count > 10000:
        result["is_excessive"] = True
        result["reason"] = f"单次查询返回 {record_count:,} 条记录，缺少分页限制"
        return result
    
    if record_count > 1000:
        result["is_excessive"] = True
        result["reason"] = f"单次查询返回 {record_count:,} 条记录，建议限制单页数量"
        return result
    
    # 检查总页数（如果有分页信息）
    pages_match = re.search(r'"totalPages"\s*:\s*(\d+)', response_text, re.IGNORECASE)
    if pages_match:
        pages = int(pages_match.group(1))
        if pages > 1000:
            result["is_excessive"] = True
            result["reason"] = f"数据总量过大 ({pages:,} 页)，可能存在权限控制不当"
    
    return result


def _detect_sensitive_business_data(response_text: str, attack_type: str) -> dict:
    """检测敏感业务数据暴露 - 基于成功响应中的实际数据判断"""
    result = {"is_sensitive": False, "categories": [], "evidence": [], "severity": None}
    
    # 1. 首先检查是否是成功响应
    if not _is_successful_response(response_text):
        return result
    
    # 2. 检查是否有实际数据
    has_data, _ = _has_actual_data(response_text)
    if not has_data:
        # 额外检查：响应太短也认为没有实际数据
        if len(response_text) < 100:
            return result
    
    # 3. 在确认有实际数据的情况下，检测敏感信息
    response_lower = response_text.lower()
    
    for category, patterns in SENSITIVE_BUSINESS_PATTERNS.items():
        matched = [p for p in patterns if p.lower() in response_lower]
        if matched:
            result["categories"].append(category)
            result["evidence"].extend(matched[:3])
    
    # 4. 只有在发现敏感字段且响应中有实际数据值时才报告
    if result["categories"]:
        # 进一步验证：检查是否有实际的数据值（而不只是字段名）
        # 例如：有 "phone" 字段且有类似手机号的值
        has_actual_values = _verify_sensitive_data_values(response_text, result["categories"])
        
        if has_actual_values:
            result["is_sensitive"] = True
            if "pii_data" in result["categories"]:
                result["severity"] = "CRITICAL"
                result["reason"] = f"发现个人隐私数据 (PII): {', '.join(result['evidence'][:5])}"
            elif "hr_data" in result["categories"] or "finance_data" in result["categories"]:
                result["severity"] = "HIGH"
                result["reason"] = f"发现敏感业务数据: {', '.join(result['evidence'][:5])}"
            else:
                result["severity"] = "MEDIUM"
                result["reason"] = f"发现组织敏感数据: {', '.join(result['evidence'][:5])}"
    
    return result


def _verify_sensitive_data_values(response_text: str, categories: list) -> bool:
    """验证响应中是否包含实际的敏感数据值（而不只是字段名）"""
    # 检查是否有实际的数据值模式
    value_patterns = [
        # 手机号
        r'1[3-9]\d{9}',
        # 身份证号
        r'\d{17}[\dXx]',
        # 邮箱
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        # 银行卡号
        r'\d{16,19}',
        # 金额（带小数）
        r'\d+\.\d{2}',
        # 日期
        r'\d{4}[-/]\d{2}[-/]\d{2}',
        # 姓名（中文2-4字）
        r'[\u4e00-\u9fa5]{2,4}',
    ]
    
    # 如果响应中有这些实际数据值的模式，认为有真实数据
    for pattern in value_patterns:
        if re.search(pattern, response_text):
            return True
    
    # 检查是否有 JSON 对象中的实际值（非空字符串）
    # 例如: "name": "张三" 而不是 "name": "" 或 "name": null
    value_with_content = re.search(r'"[^"]+"\s*:\s*"[^"]{2,}"', response_text)
    if value_with_content:
        return True
    
    return False


def _detect_idor(response_text: str, payload: str) -> dict:
    """检测越权访问 - 基于成功获取他人数据判断"""
    result = {"is_idor": False, "reason": "", "evidence": []}
    
    # 1. 首先检查是否是成功响应
    if not _is_successful_response(response_text):
        return result
    
    # 2. 检查是否有实际数据
    has_data, _ = _has_actual_data(response_text)
    if not has_data and len(response_text) < 100:
        return result
    
    # 3. 使用测试 ID 成功获取到数据才算 IDOR
    test_ids = ["1", "0", "admin", "root", "000001", "100001", "-1", "999999"]
    
    if payload in test_ids:
        # 检查是否返回了用户相关数据
        user_indicators = ["username", "user_name", "userId", "employeeId", 
                          "姓名", "员工", "用户", "email", "phone", "mobile"]
        found = [ind for ind in user_indicators if ind.lower() in response_text.lower()]
        
        # 进一步验证：必须有实际的数据值
        if found and _verify_sensitive_data_values(response_text, ["pii_data"]):
            result["is_idor"] = True
            result["reason"] = f"使用测试ID '{payload}' 成功获取到用户数据"
            result["evidence"] = found[:3]
    
    return result


async def recon_target(url: str, token: str = "") -> dict:
    """侦察目标 MCP 服务器，获取所有可用工具列表"""
    headers = {}
    if token:
        clean_token = token.strip()
        if not clean_token.lower().startswith(("bearer ", "basic ")):
            clean_token = f"Bearer {clean_token}"
        headers["Authorization"] = clean_token
    
    print(f"[Tool:Recon] 侦察目标: {url}", file=sys.stderr)
    
    try:
        async with sse_client(url, headers=headers, timeout=15.0) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()
                
                tools = []
                attack_surface = []
                static_vulnerabilities = []
                
                for t in result.tools:
                    tool_info = {
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.inputSchema,
                    }
                    tools.append(tool_info)
                    
                    # 检测硬编码凭据
                    cred_vulns = _detect_hardcoded_credentials(t.name, t.inputSchema)
                    static_vulnerabilities.extend(cred_vulns)
                    
                    # 检测工具描述注入
                    desc_vulns = _detect_description_injection(t.name, t.description or "")
                    static_vulnerabilities.extend(desc_vulns)
                    
                    # 分析可注入参数
                    string_params = [
                        p for p, info in t.inputSchema.get("properties", {}).items()
                        if info.get("type") == "string"
                    ]
                    
                    if string_params:
                        # 智能识别工具类型
                        tool_type_info = identify_tool_type(t.name, t.description or "", string_params)
                        
                        # 生成智能攻击计划
                        smart_attacks = generate_smart_payloads(t.name, t.description or "", t.inputSchema)
                        
                        priority = "high" if tool_type_info["confidence"] >= 2 else "medium"
                        
                        attack_surface.append({
                            "tool_name": t.name,
                            "injectable_params": string_params,
                            "priority": priority,
                            "schema": t.inputSchema,
                            "tool_type": tool_type_info["tool_type"],
                            "recommended_attacks": tool_type_info["recommended_attacks"],
                            "smart_attack_plans": smart_attacks,
                        })
                
                print(f"[Tool:Recon] 发现 {len(tools)} 个工具, {len(attack_surface)} 个可注入, {len(static_vulnerabilities)} 个静态漏洞", file=sys.stderr)
                
                return {
                    "status": "success",
                    "tools_count": len(tools),
                    "tools": tools,
                    "attack_surface": attack_surface,
                    "static_vulnerabilities": static_vulnerabilities,
                    "static_vuln_count": len(static_vulnerabilities),
                }
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def execute_injection(url: str, tool_name: str, attack_type: str, payload: str, schema: dict, token: str = "") -> dict:
    """对目标工具执行单次注入攻击"""
    headers = {}
    if token:
        clean_token = token.strip()
        if not clean_token.lower().startswith(("bearer ", "basic ")):
            clean_token = f"Bearer {clean_token}"
        headers["Authorization"] = clean_token
    
    test_args = {}
    properties = schema.get("properties", {})
    for param_name, param_info in properties.items():
        param_type = param_info.get("type", "string")
        if param_type == "string":
            test_args[param_name] = payload
        elif param_type == "integer":
            test_args[param_name] = 1
        elif param_type == "number":
            test_args[param_name] = 1.0
        elif param_type == "boolean":
            test_args[param_name] = True
    
    # 确保 payload 是字符串
    if not isinstance(payload, str):
        payload = str(payload) if payload is not None else ""
    
    print(f"[Tool:Inject] {tool_name} <- {attack_type}: {payload[:50]}...", file=sys.stderr)
    
    try:
        async with sse_client(url, headers=headers, timeout=30.0) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, test_args)
                
                response_text = ""
                for content in result.content:
                    response_text += getattr(content, "text", str(content))
                
                is_vulnerable = False
                detected_patterns = []
                vulnerability_details = {}
                severity = None
                response_lower = response_text.lower()
                
                # 0. 首先检查是否是错误响应（错误响应中的敏感模式不算漏洞）
                is_error_response = not _is_successful_response(response_text)
                
                # 1. 检测高可信度敏感信息模式（仅在非错误响应中检测）
                if not is_error_response:
                    for pattern in SENSITIVE_PATTERNS_HIGH_CONFIDENCE:
                        if pattern.lower() in response_lower:
                            is_vulnerable = True
                            detected_patterns.append(f"敏感信息泄露: {pattern}")
                            severity = "CRITICAL"
                
                # 2. 检测过度数据暴露
                if attack_type == "mcp_excessive_data_exposure":
                    excessive_data = _detect_excessive_data(response_text)
                    if excessive_data["is_excessive"]:
                        is_vulnerable = True
                        detected_patterns.append(f"过度数据暴露: {excessive_data['reason']}")
                        vulnerability_details["excessive_data"] = excessive_data
                        severity = "HIGH" if severity is None else severity
                
                # 3. 检测越权访问
                if attack_type == "mcp_idor":
                    idor_result = _detect_idor(response_text, payload)
                    if idor_result["is_idor"]:
                        is_vulnerable = True
                        detected_patterns.append(f"越权访问: {idor_result['reason']}")
                        vulnerability_details["idor"] = idor_result
                        severity = "HIGH" if severity is None else severity
                
                # 4. 检测敏感业务数据
                if attack_type == "mcp_sensitive_business_probe":
                    sensitive_result = _detect_sensitive_business_data(response_text, attack_type)
                    if sensitive_result["is_sensitive"]:
                        is_vulnerable = True
                        detected_patterns.append(f"敏感数据暴露: {sensitive_result['reason']}")
                        vulnerability_details["sensitive_business"] = sensitive_result
                        severity = sensitive_result["severity"] if severity is None else severity
                
                # 5. 命令注入/代码执行成功检测
                if attack_type in ["mcp_command_injection", "mcp_code_execution"]:
                    cmd_success_patterns = ["root:x:0:0:", "uid=", "drwxr-xr-x", "total "]
                    for pattern in cmd_success_patterns:
                        if pattern in response_text:
                            is_vulnerable = True
                            detected_patterns.append(f"命令执行成功: 响应包含 '{pattern}'")
                            severity = "CRITICAL"
                            break
                
                # 最终严重程度校验
                if severity is None and is_vulnerable:
                    severity = "MEDIUM"
                
                return {
                    "status": "success",
                    "tool_name": tool_name,
                    "attack_type": attack_type,
                    "payload": payload,
                    "actual_args": test_args,
                    "response_preview": response_text[:500],
                    "response_length": len(response_text),
                    "is_vulnerable": is_vulnerable,
                    "detected_patterns": detected_patterns,
                    "severity": severity,
                    "details": vulnerability_details,
                }
    except Exception as e:
        return {"status": "error", "tool_name": tool_name, "attack_type": attack_type, "payload": payload, "error": str(e)}


def analyze_results(attack_results: list) -> dict:
    """分析所有攻击结果，生成安全报告 - 基于漏洞严重程度综合评估"""
    vulnerabilities = []
    successful_attacks = 0
    failed_attacks = 0
    
    # 严重程度计数
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    for result in attack_results:
        if result.get("status") == "error":
            failed_attacks += 1
            continue
        
        successful_attacks += 1
        if result.get("is_vulnerable"):
            sev = result.get("severity", "MEDIUM")
            if sev in severity_counts:
                severity_counts[sev] += 1
            
            vulnerabilities.append({
                "tool_name": result["tool_name"],
                "attack_type": result["attack_type"],
                "payload": result["payload"],
                "severity": sev,
                "evidence": result["detected_patterns"],
                "response_preview": result.get("response_preview", ""),
                "response_length": result.get("response_length", 0),
                "details": result.get("details", {}),
            })
    
    # 基于漏洞严重程度综合评估风险等级
    # CRITICAL 漏洞 -> CRITICAL 风险
    # HIGH 漏洞 >= 2 或 CRITICAL >= 1 -> HIGH 风险
    # MEDIUM 漏洞 >= 3 或 HIGH >= 1 -> MEDIUM 风险
    # 其他 -> LOW 风险
    if severity_counts["CRITICAL"] >= 1:
        risk_level = "CRITICAL"
    elif severity_counts["HIGH"] >= 2 or (severity_counts["HIGH"] >= 1 and severity_counts["MEDIUM"] >= 2):
        risk_level = "HIGH"
    elif severity_counts["HIGH"] >= 1 or severity_counts["MEDIUM"] >= 3:
        risk_level = "MEDIUM"
    elif len(vulnerabilities) > 0:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"
    
    return {
        "risk_level": risk_level,
        "total_tests": len(attack_results),
        "successful_tests": successful_attacks,
        "failed_tests": failed_attacks,
        "vulnerabilities_found": len(vulnerabilities),
        "severity_breakdown": severity_counts,
        "vulnerabilities": vulnerabilities,
    }


def get_payloads(attack_type: str, limit: int = 2) -> list:
    """获取指定攻击类型的载荷列表"""
    payloads = INJECTION_PAYLOADS.get(attack_type, [])
    return payloads[:limit]


def list_attack_types() -> list:
    """列出所有可用的攻击类型"""
    return list(INJECTION_PAYLOADS.keys())


__all__ = [
    "recon_target",
    "execute_injection",
    "analyze_results",
    "get_payloads",
    "list_attack_types",
    "identify_tool_type",
    "generate_smart_payloads",
    "analyze_tool_behavior",
    "detect_permission_issues",
]


# ============================================================
# TODO 6.1: 工具行为分析
# ============================================================

def analyze_tool_behavior(tool_name: str, responses: List[Dict]) -> Dict:
    """分析工具的行为模式，检测异常"""
    analysis = {
        "tool_name": tool_name,
        "total_calls": len(responses),
        "success_rate": 0,
        "avg_response_size": 0,
        "anomalies": [],
        "behavior_patterns": [],
    }
    
    if not responses:
        return analysis
    
    # 统计成功率
    success_count = sum(1 for r in responses if r.get("status") == "success")
    analysis["success_rate"] = success_count / len(responses) * 100
    
    # 统计响应大小
    response_sizes = [r.get("response_length", 0) for r in responses if r.get("status") == "success"]
    if response_sizes:
        analysis["avg_response_size"] = sum(response_sizes) / len(response_sizes)
        analysis["max_response_size"] = max(response_sizes)
        analysis["min_response_size"] = min(response_sizes)
    
    # 检测异常行为
    for resp in responses:
        if resp.get("status") != "success":
            continue
        
        response_size = resp.get("response_length", 0)
        
        # 1. 响应过大（可能数据泄露）
        if response_size > 50 * 1024:  # 50KB
            analysis["anomalies"].append({
                "type": "large_response",
                "severity": "MEDIUM",
                "description": f"响应数据过大 ({response_size // 1024}KB)",
                "payload": resp.get("payload", ""),
            })
        
        # 2. 检测敏感数据返回
        response_preview = resp.get("response_preview", "")
        if any(pattern in response_preview.lower() for pattern in ["password", "secret", "token", "key"]):
            analysis["anomalies"].append({
                "type": "sensitive_data_exposure",
                "severity": "HIGH",
                "description": "响应中可能包含敏感数据",
                "payload": resp.get("payload", ""),
            })
        
        # 3. 检测错误信息泄露
        error_patterns = ["stack trace", "traceback", "exception", "error at line"]
        if any(pattern in response_preview.lower() for pattern in error_patterns):
            analysis["anomalies"].append({
                "type": "error_disclosure",
                "severity": "LOW",
                "description": "响应中包含详细错误信息",
                "payload": resp.get("payload", ""),
            })
    
    # 行为模式分析
    if analysis["success_rate"] == 100:
        analysis["behavior_patterns"].append("所有请求都成功，可能缺少输入验证")
    
    if analysis["avg_response_size"] > 10 * 1024:
        analysis["behavior_patterns"].append("平均响应较大，可能返回过多数据")
    
    return analysis


def detect_permission_issues(tool_info: Dict, responses: List[Dict]) -> List[Dict]:
    """检测工具权限问题"""
    issues = []
    tool_name = tool_info.get("name", "")
    description = (tool_info.get("description") or "").lower()
    
    # 1. 检测过度授权 - 工具描述暗示高权限操作
    high_privilege_keywords = ["admin", "root", "system", "all", "any", "管理员", "所有", "任意"]
    for keyword in high_privilege_keywords:
        if keyword in description:
            issues.append({
                "type": "excessive_permission",
                "tool_name": tool_name,
                "severity": "MEDIUM",
                "description": f"工具描述包含高权限关键词 '{keyword}'",
                "recommendation": "检查工具是否需要如此高的权限"
            })
            break
    
    # 2. 检测无限制数据访问
    for resp in responses:
        if resp.get("status") != "success":
            continue
        
        # 检查是否能访问大量数据
        response_text = resp.get("response_preview", "")
        total_match = re.search(r'"total"\s*:\s*(\d+)', response_text)
        if total_match:
            total = int(total_match.group(1))
            if total > 1000:
                issues.append({
                    "type": "unrestricted_data_access",
                    "tool_name": tool_name,
                    "severity": "HIGH",
                    "description": f"工具可访问 {total:,} 条记录，缺少数据访问限制",
                    "recommendation": "实施数据访问控制和分页限制"
                })
    
    return issues
