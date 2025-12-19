"""状态定义：LangGraph 共享状态"""

from typing import TypedDict


class ScannerState(TypedDict):
    """安全扫描器的共享状态"""
    # 消息历史 (可选，用于日志)
    messages: list
    
    # 目标信息
    target_url: str
    target_token: str
    headers: dict
    
    # 侦察结果
    discovered_tools: list  # 发现的工具列表
    attack_surface: list    # 可攻击的工具和参数
    
    # 攻击过程
    current_tool: str       # 当前正在测试的工具
    current_attack_type: str  # 当前攻击类型
    pending_attacks: list   # 待执行的攻击队列
    
    # 结果收集
    attack_results: list    # 所有攻击结果
    vulnerabilities: list   # 发现的漏洞
    
    # 控制流
    next_action: str        # 下一步动作: continue, finish
    error: str              # 错误信息
