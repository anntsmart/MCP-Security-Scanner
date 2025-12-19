"""异步任务管理器：管理后台扫描任务"""
import asyncio
import uuid
import sys
from datetime import datetime
from typing import Dict, Any, Optional
from enum import Enum


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanTask:
    """扫描任务"""
    
    def __init__(self, task_id: str, url: str, token: str):
        self.task_id = task_id
        self.url = url
        self.token = token
        self.status = TaskStatus.PENDING
        self.progress = 0
        self.current_step = ""
        self.current_phase = "初始化"  # 当前阶段
        self.logs = []
        self.result = None
        self.error = None
        self.created_at = datetime.now()
        self.started_at = None
        self.completed_at = None
        
        # 阶段性数据（实时更新）
        self.recon_data = None  # 侦察阶段数据
        self.attack_progress = {  # 攻击进度
            "total_tools": 0,
            "tested_tools": 0,
            "total_attacks": 0,
            "completed_attacks": 0,
            "vulnerabilities_found": 0
        }
    
    def log(self, message: str):
        """添加日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.logs.append(log_entry)
        print(f"[Task:{self.task_id[:8]}] {message}", file=sys.stderr)
    
    def set_recon_data(self, tools: list, attack_surface: list):
        """设置侦察阶段数据"""
        self.recon_data = {
            "tools_count": len(tools),
            "tools": [{"name": t.get("name"), "description": t.get("description", "")[:100]} for t in tools],
            "injectable_count": len(attack_surface),
            "attack_surface": [
                {
                    "tool_name": s.get("tool_name"),
                    "injectable_params": s.get("injectable_params", []),
                    "priority": s.get("priority", "medium")
                }
                for s in attack_surface
            ]
        }
        self.attack_progress["total_tools"] = len(attack_surface)
    
    def update_attack_progress(self, tested_tools: int = None, completed_attacks: int = None, vulns: int = None):
        """更新攻击进度"""
        if tested_tools is not None:
            self.attack_progress["tested_tools"] = tested_tools
        if completed_attacks is not None:
            self.attack_progress["completed_attacks"] = completed_attacks
        if vulns is not None:
            self.attack_progress["vulnerabilities_found"] = vulns
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "task_id": self.task_id,
            "url": self.url,
            "status": self.status.value,
            "progress": self.progress,
            "current_step": self.current_step,
            "current_phase": self.current_phase,
            "logs": self.logs[-20:],
            "recon_data": self.recon_data,
            "attack_progress": self.attack_progress,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class TaskManager:
    """任务管理器 - 单例模式"""
    
    _instance = None
    _tasks: Dict[str, ScanTask] = {}
    _running_tasks: Dict[str, asyncio.Task] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def create_task(self, url: str, token: str) -> ScanTask:
        """创建新任务"""
        task_id = str(uuid.uuid4())
        task = ScanTask(task_id, url, token)
        self._tasks[task_id] = task
        return task
    
    def get_task(self, task_id: str) -> Optional[ScanTask]:
        """获取任务"""
        return self._tasks.get(task_id)
    
    def list_tasks(self) -> list:
        """列出所有任务"""
        return [t.to_dict() for t in self._tasks.values()]
    
    def clear_task(self, task_id: str) -> bool:
        """清除指定任务"""
        if task_id in self._tasks:
            del self._tasks[task_id]
            if task_id in self._running_tasks:
                self._running_tasks[task_id].cancel()
                del self._running_tasks[task_id]
            return True
        return False
    
    def clear_all_tasks(self):
        """清除所有任务"""
        for task_id in list(self._running_tasks.keys()):
            self._running_tasks[task_id].cancel()
        self._tasks.clear()
        self._running_tasks.clear()
    
    async def start_task(self, task: ScanTask, scan_func):
        """启动后台任务"""
        async def run_scan():
            try:
                task.status = TaskStatus.RUNNING
                task.started_at = datetime.now()
                task.log("扫描任务开始")
                
                # 执行扫描
                result = await scan_func(task)
                
                task.result = result
                task.status = TaskStatus.COMPLETED
                task.progress = 100
                task.completed_at = datetime.now()
                task.log("扫描任务完成")
                
            except Exception as e:
                task.error = str(e)
                task.status = TaskStatus.FAILED
                task.completed_at = datetime.now()
                task.log(f"扫描任务失败: {e}")
        
        # 创建后台任务
        asyncio_task = asyncio.create_task(run_scan())
        self._running_tasks[task.task_id] = asyncio_task
        return task


# 全局任务管理器实例
task_manager = TaskManager()
