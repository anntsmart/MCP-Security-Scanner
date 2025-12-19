"""ReAct Agent：自主执行 MCP 安全扫描
"""
import sys
import json
import re
import html
import asyncio
from typing import Dict, List, Any
from .llm import LLM
from .tools import (
    recon_target, execute_injection, analyze_results, 
    get_payloads, list_attack_types,
    identify_tool_type, generate_smart_payloads
)


def parse_tool_invocations(content: str) -> List[Dict[str, Any]]:
    """解析工具调用"""
    tool_invocations = []
    
    # 格式: <function=tool_name><parameter=param>value</parameter></function>
    fn_regex = r"<function=([^>]+)>\n?(.*?)</function.*?>"
    param_regex = r"<parameter=([^>]+)>(.*?)</parameter>"
    
    fn_matches = re.finditer(fn_regex, content, re.DOTALL)
    
    for fn_match in fn_matches:
        fn_name = fn_match.group(1).strip()
        fn_body = fn_match.group(2)
        
        args = {}
        param_matches = re.finditer(param_regex, fn_body, re.DOTALL)
        for param_match in param_matches:
            param_name = param_match.group(1).strip()
            param_value = html.unescape(param_match.group(2).strip())
            try:
                args[param_name] = json.loads(param_value)
            except:
                args[param_name] = param_value
        
        tool_invocations.append({"name": fn_name, "args": args})
    
    return tool_invocations


class SecurityAgent:
    """MCP 安全扫描智能体 - ReAct 模式"""
    
    def __init__(self, llm_provider: str = "qwen", llm_model: str = "qwen-max"):
        self.llm = LLM(provider=llm_provider, model=llm_model)
        self.history = []
        self.scan_context = {}
        self.max_iter = 30
        self.is_finished = False
        self.task = None  # 关联的任务对象

    def _get_system_prompt(self) -> str:
        """生成系统提示词"""
        return """你是一个专业的 MCP 安全扫描智能体。你的任务是自主执行安全扫描。

## 可用工具

### recon_target - 侦察目标，获取工具列表
<function=recon_target>
<parameter=url>目标URL</parameter>
<parameter=token>认证Token（可选）</parameter>
</function>

### list_attack_types - 列出所有攻击类型
<function=list_attack_types>
</function>

### get_payloads - 获取攻击载荷
<function=get_payloads>
<parameter=attack_type>攻击类型</parameter>
<parameter=limit>数量限制</parameter>
</function>

### execute_injection - 执行注入攻击测试
<function=execute_injection>
<parameter=tool_name>工具名称</parameter>
<parameter=attack_type>攻击类型</parameter>
<parameter=payload>攻击载荷</parameter>
<parameter=schema>工具schema（JSON格式）</parameter>
</function>

### analyze_results - 分析攻击结果
<function=analyze_results>
</function>

### finish - 完成扫描
<function=finish>
<parameter=summary>扫描总结</parameter>
</function>

## 扫描流程

1. 调用 recon_target 获取目标的所有工具和攻击面
2. 调用 list_attack_types 获取可用攻击类型
3. 对每个 attack_surface 中的工具，按以下优先级测试：
   - **必测**: mcp_excessive_data_exposure (过度数据暴露，用空字符串""测试)
   - **必测**: mcp_sensitive_business_probe (敏感业务数据)
   - **必测**: mcp_idor (越权访问)
   - 可选: mcp_command_injection, mcp_sql_injection
4. 完成所有测试后调用 analyze_results 生成报告
5. 调用 finish 结束扫描

## 攻击类型说明

- mcp_excessive_data_exposure: 测试是否返回大量数据（用空字符串""作为payload）
- mcp_sensitive_business_probe: 测试是否暴露HR/财务/个人信息
- mcp_idor: 测试是否能越权访问他人数据（用"1","admin"等作为payload）
- mcp_command_injection: 命令注入测试
- mcp_sql_injection: SQL注入测试

## 重要规则

- 每次响应只调用一个工具
- 必须等待工具结果后再继续
- 使用上述 XML 格式调用工具
- 不要假设结果，必须实际执行
- 每个工具至少测试 mcp_excessive_data_exposure 和 mcp_sensitive_business_probe
"""

    def _log(self, message: str):
        """记录日志到任务"""
        if self.task:
            self.task.log(message)
        else:
            print(f"[Agent] {message}", file=sys.stderr)
    
    def _update_progress(self, progress: int, step: str):
        """更新任务进度"""
        if self.task:
            self.task.progress = progress
            self.task.current_step = step

    async def scan(self, task=None) -> Dict[str, Any]:
        """执行完整安全扫描"""
        self.task = task
        url = task.url if task else ""
        token = task.token if task else ""
        
        self._log(f"启动自主扫描: {url}")
        self._update_progress(5, "初始化")
        
        # 初始化
        self.scan_context = {
            "url": url,
            "token": token,
            "tools": [],
            "attack_surface": [],
            "attack_results": [],
        }
        self.is_finished = False
        
        # 初始化对话
        self.history = [
            {"role": "system", "content": self._get_system_prompt()},
            {"role": "user", "content": f"""请对以下 MCP 服务进行完整的安全扫描：

目标 URL: {url}
Token: {token if token else '无'}

请开始执行扫描，首先调用 recon_target 获取目标信息。"""}
        ]
        
        # ReAct 主循环
        iteration = 0
        while not self.is_finished and iteration < self.max_iter:
            iteration += 1
            self._log(f"迭代 {iteration}/{self.max_iter}")
            self._update_progress(min(10 + iteration * 3, 90), f"迭代 {iteration}")
            
            # 调用 LLM
            try:
                response = self.llm.chat(self.history, temperature=0.1)
            except Exception as e:
                self._log(f"LLM 调用失败: {e}")
                break
            
            if not response:
                self._log("LLM 返回空响应")
                continue
            
            self._log(f"LLM: {response[:100]}...")
            self.history.append({"role": "assistant", "content": response})
            
            # 解析工具调用
            tool_invocations = parse_tool_invocations(response)
            
            if not tool_invocations:
                self._log("未检测到工具调用")
                self.history.append({
                    "role": "user",
                    "content": """未检测到工具调用。请使用正确的 XML 格式：
<function=工具名>
<parameter=参数名>参数值</parameter>
</function>

请继续执行扫描。"""
                })
                continue
            
            # 执行第一个工具
            tool = tool_invocations[0]
            tool_name = tool["name"]
            tool_args = tool["args"]
            
            self._log(f"执行工具: {tool_name}")
            self._update_progress(min(10 + iteration * 3, 90), f"执行 {tool_name}")
            
            result = await self._execute_tool(tool_name, tool_args)
            self._log(f"工具结果: {str(result)[:100]}...")
            
            # 检查是否完成
            if tool_name == "finish":
                self.is_finished = True
                break
            
            # 反馈结果给 LLM
            result_str = json.dumps(result, ensure_ascii=False, indent=2, default=str)
            self.history.append({
                "role": "user",
                "content": f"""工具执行结果：
<tool_name>{tool_name}</tool_name>
<tool_result>
{result_str[:2000]}
</tool_result>

请根据结果继续执行下一步。当前迭代: {iteration}"""
            })
        
        # 生成最终报告
        self._update_progress(95, "生成报告")
        return self._generate_report()

    def _update_phase(self, phase: str):
        """更新当前阶段"""
        if self.task:
            self.task.current_phase = phase

    async def _execute_tool(self, name: str, args: Dict[str, Any]) -> Any:
        """执行工具调用"""
        url = self.scan_context["url"]
        token = self.scan_context["token"]
        
        try:
            if name == "recon_target":
                self._update_phase("侦察阶段")
                result = await recon_target(
                    args.get("url", url),
                    args.get("token", token)
                )
                if result.get("status") == "success":
                    tools = result.get("tools", [])
                    attack_surface = result.get("attack_surface", [])
                    static_vulns = result.get("static_vulnerabilities", [])
                    
                    self.scan_context["tools"] = tools
                    self.scan_context["attack_surface"] = attack_surface
                    self.scan_context["static_vulnerabilities"] = static_vulns
                    
                    # 将静态漏洞也加入攻击结果
                    for vuln in static_vulns:
                        self.scan_context["attack_results"].append({
                            "status": "success",
                            "tool_name": vuln.get("tool_name", ""),
                            "attack_type": vuln.get("type", "hardcoded_credential"),
                            "payload": vuln.get("param_name", "N/A"),
                            "is_vulnerable": True,
                            "severity": vuln.get("severity", "HIGH"),
                            "detected_patterns": [vuln.get("evidence", "")],
                            "response_preview": vuln.get("evidence", ""),  # 静态漏洞的证据就是响应
                            "recommendation": vuln.get("recommendation", ""),
                        })
                    
                    # 更新任务的侦察数据（供前端实时查看）
                    if self.task:
                        self.task.set_recon_data(tools, attack_surface)
                        self._log(f"侦察完成: 发现 {len(tools)} 个工具, {len(attack_surface)} 个可注入, {len(static_vulns)} 个静态漏洞")
                
                return result
            
            elif name == "list_attack_types":
                self._update_phase("准备攻击")
                return {"status": "success", "attack_types": list_attack_types()}
            
            elif name == "get_payloads":
                attack_type = args.get("attack_type", "mcp_command_injection")
                limit = int(args.get("limit", 3))
                return {"status": "success", "payloads": get_payloads(attack_type, limit)}
            
            elif name == "execute_injection":
                self._update_phase("攻击测试")
                
                # 获取并验证 schema
                schema = args.get("schema", {})
                if isinstance(schema, str):
                    try:
                        schema = json.loads(schema)
                    except:
                        schema = {}
                
                # 如果 schema 为空，从 attack_surface 中查找
                tool_name = args.get("tool_name", "")
                if not schema or not isinstance(schema, dict):
                    for surface in self.scan_context.get("attack_surface", []):
                        if surface.get("tool_name") == tool_name:
                            schema = surface.get("schema", {})
                            break
                
                # 确保 payload 是字符串
                payload = args.get("payload", "")
                if not isinstance(payload, str):
                    payload = str(payload) if payload is not None else ""
                
                result = await execute_injection(
                    url,
                    tool_name,
                    args.get("attack_type", ""),
                    payload,
                    schema,
                    token
                )
                self.scan_context["attack_results"].append(result)
                
                # 更新攻击进度
                if self.task:
                    attack_results = self.scan_context["attack_results"]
                    vulns = len([r for r in attack_results if r.get("is_vulnerable")])
                    self.task.update_attack_progress(
                        completed_attacks=len(attack_results),
                        vulns=vulns
                    )
                
                return result
            
            elif name == "analyze_results":
                self._update_phase("分析结果")
                results = self.scan_context["attack_results"]
                return analyze_results(results)
            
            elif name == "finish":
                self._update_phase("完成")
                self.is_finished = True
                return {"status": "finished", "summary": args.get("summary", "")}
            
            else:
                return {"status": "error", "error": f"未知工具: {name}"}
        
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def _execute_concurrent_attacks(self, attack_plans: List[Dict], url: str, token: str, max_concurrent: int = 5) -> List[Dict]:
        """并发执行多个攻击测试"""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def execute_with_semaphore(plan: Dict) -> Dict:
            async with semaphore:
                try:
                    result = await execute_injection(
                        url,
                        plan["tool_name"],
                        plan["attack_type"],
                        plan["payload"],
                        plan["schema"],
                        token
                    )
                    return result
                except Exception as e:
                    return {
                        "status": "error",
                        "tool_name": plan["tool_name"],
                        "attack_type": plan["attack_type"],
                        "payload": plan["payload"],
                        "error": str(e)
                    }
        
        # 创建所有任务
        tasks = [execute_with_semaphore(plan) for plan in attack_plans]
        
        # 并发执行
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理结果
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    "status": "error",
                    "tool_name": attack_plans[i]["tool_name"],
                    "attack_type": attack_plans[i]["attack_type"],
                    "error": str(result)
                })
            else:
                processed_results.append(result)
        
        return processed_results

    async def fast_scan(self, task=None) -> Dict[str, Any]:
        """快速扫描模式 - 使用智能 payload 和并发执行"""
        self.task = task
        url = task.url if task else ""
        token = task.token if task else ""
        
        self._log(f"启动快速扫描: {url}")
        self._update_progress(5, "初始化")
        
        # 初始化
        self.scan_context = {
            "url": url,
            "token": token,
            "tools": [],
            "attack_surface": [],
            "attack_results": [],
        }
        
        # 1. 侦察阶段
        self._update_phase("侦察阶段")
        self._update_progress(10, "侦察目标")
        recon_result = await recon_target(url, token)
        
        if recon_result.get("status") != "success":
            self._log(f"侦察失败: {recon_result.get('error')}")
            return {"status": "error", "error": recon_result.get("error")}
        
        tools = recon_result.get("tools", [])
        attack_surface = recon_result.get("attack_surface", [])
        static_vulns = recon_result.get("static_vulnerabilities", [])
        
        self.scan_context["tools"] = tools
        self.scan_context["attack_surface"] = attack_surface
        
        # 添加静态漏洞
        for vuln in static_vulns:
            self.scan_context["attack_results"].append({
                "status": "success",
                "tool_name": vuln.get("tool_name", ""),
                "attack_type": vuln.get("type", "hardcoded_credential"),
                "payload": vuln.get("param_name", "N/A"),
                "is_vulnerable": True,
                "severity": vuln.get("severity", "HIGH"),
                "detected_patterns": [vuln.get("evidence", "")],
                "response_preview": vuln.get("evidence", ""),
            })
        
        if self.task:
            self.task.set_recon_data(tools, attack_surface)
        
        self._log(f"侦察完成: {len(tools)} 工具, {len(attack_surface)} 可注入, {len(static_vulns)} 静态漏洞")
        
        # 2. 生成智能攻击计划
        self._update_phase("生成攻击计划")
        self._update_progress(20, "生成攻击计划")
        
        all_attack_plans = []
        for surface in attack_surface:
            tool_name = surface["tool_name"]
            schema = surface["schema"]
            smart_plans = surface.get("smart_attack_plans", [])
            
            # 使用智能生成的攻击计划
            for plan in smart_plans:
                for payload in plan["payloads"]:
                    all_attack_plans.append({
                        "tool_name": tool_name,
                        "attack_type": plan["attack_type"],
                        "payload": payload,
                        "schema": schema,
                    })
        
        self._log(f"生成 {len(all_attack_plans)} 个攻击计划")
        
        # 3. 并发执行攻击
        self._update_phase("并发攻击测试")
        total_plans = len(all_attack_plans)
        
        if total_plans > 0:
            # 分批执行，每批最多 10 个
            batch_size = 10
            for i in range(0, total_plans, batch_size):
                batch = all_attack_plans[i:i+batch_size]
                progress = 20 + int((i / total_plans) * 60)
                self._update_progress(progress, f"执行攻击 {i+1}-{min(i+batch_size, total_plans)}/{total_plans}")
                
                batch_results = await self._execute_concurrent_attacks(batch, url, token, max_concurrent=5)
                self.scan_context["attack_results"].extend(batch_results)
                
                # 更新进度
                if self.task:
                    vulns = len([r for r in self.scan_context["attack_results"] if r.get("is_vulnerable")])
                    self.task.update_attack_progress(
                        completed_attacks=len(self.scan_context["attack_results"]),
                        vulns=vulns
                    )
        
        # 4. 分析结果
        self._update_phase("分析结果")
        self._update_progress(90, "分析结果")
        
        # 5. 生成报告
        self._update_progress(95, "生成报告")
        return self._generate_report()

    def _generate_report(self) -> Dict[str, Any]:
        """生成最终扫描报告"""
        tools = self.scan_context.get("tools", [])
        attack_surface = self.scan_context.get("attack_surface", [])
        attack_results = self.scan_context.get("attack_results", [])
        
        # 使用 analyze_results 进行分析
        analysis = analyze_results(attack_results)
        
        return {
            "status": "completed",
            "target": self.scan_context["url"],
            "risk_level": analysis["risk_level"],
            "summary": {
                "tools_discovered": len(tools),
                "injectable_tools": len(attack_surface),
                "attacks_executed": analysis["total_tests"],
                "vulnerabilities_found": analysis["vulnerabilities_found"],
            },
            "severity_breakdown": analysis.get("severity_breakdown", {}),
            "tools": tools,
            "attack_surface": attack_surface,
            "vulnerabilities": analysis["vulnerabilities"],
            "attack_details": attack_results,
        }
