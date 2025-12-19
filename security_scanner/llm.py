"""LLM 客户端：支持通义千问和 Azure OpenAI"""

import httpx
from typing import Generator, Optional


class LLM:
    """统一的 LLM 接口"""
    
    def __init__(
        self,
        provider: str = "qwen",  # qwen 或 azure
        model: str = "qwen-max",
        api_key: str = None,
        base_url: str = None,
    ):
        self.provider = provider
        self.model = model
        
        if provider == "qwen":
            self.api_key = api_key or "sk-"
            self.base_url = base_url or "https://dashscope.aliyuncs.com/compatible-mode/v1"
        elif provider == "azure":
            self.api_key = api_key or ""
            self.base_url = base_url or "https://xxxx-openai-dev-006.openai.azure.com/openai/deployments/gpt-4o"
            self.api_version = "2024-10-21"
        else:
            raise ValueError(f"不支持的 provider: {provider}")
    
    def chat(self, messages: list, temperature: float = 0.7) -> str:
        """同步聊天"""
        if self.provider == "qwen":
            return self._chat_qwen(messages, temperature)
        elif self.provider == "azure":
            return self._chat_azure(messages, temperature)
    
    def _chat_qwen(self, messages: list, temperature: float) -> str:
        """通义千问 API"""
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        data = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        
        with httpx.Client(timeout=120.0) as client:
            response = client.post(url, headers=headers, json=data)
            response.raise_for_status()
            result = response.json()
            return result["choices"][0]["message"]["content"]
    
    def _chat_azure(self, messages: list, temperature: float) -> str:
        """Azure OpenAI API"""
        url = f"{self.base_url}/chat/completions?api-version={self.api_version}"
        headers = {
            "Content-Type": "application/json",
            "api-key": self.api_key,
        }
        data = {
            "messages": messages,
            "temperature": temperature,
        }
        
        with httpx.Client(timeout=120.0) as client:
            response = client.post(url, headers=headers, json=data)
            response.raise_for_status()
            result = response.json()
            return result["choices"][0]["message"]["content"]
    
    def chat_stream(self, messages: list, temperature: float = 0.7) -> Generator[str, None, None]:
        """流式聊天"""
        if self.provider == "qwen":
            yield from self._chat_stream_qwen(messages, temperature)
        elif self.provider == "azure":
            yield from self._chat_stream_azure(messages, temperature)
    
    def _chat_stream_qwen(self, messages: list, temperature: float) -> Generator[str, None, None]:
        """通义千问流式 API"""
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        data = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "stream": True,
        }
        
        with httpx.Client(timeout=120.0) as client:
            with client.stream("POST", url, headers=headers, json=data) as response:
                for line in response.iter_lines():
                    if line.startswith("data: "):
                        content = line[6:]
                        if content == "[DONE]":
                            break
                        try:
                            import json
                            chunk = json.loads(content)
                            delta = chunk["choices"][0].get("delta", {})
                            if "content" in delta:
                                yield delta["content"]
                        except:
                            pass
    
    def _chat_stream_azure(self, messages: list, temperature: float) -> Generator[str, None, None]:
        """Azure OpenAI 流式 API"""
        url = f"{self.base_url}/chat/completions?api-version={self.api_version}"
        headers = {
            "Content-Type": "application/json",
            "api-key": self.api_key,
        }
        data = {
            "messages": messages,
            "temperature": temperature,
            "stream": True,
        }
        
        with httpx.Client(timeout=120.0) as client:
            with client.stream("POST", url, headers=headers, json=data) as response:
                for line in response.iter_lines():
                    if line.startswith("data: "):
                        content = line[6:]
                        if content == "[DONE]":
                            break
                        try:
                            import json
                            chunk = json.loads(content)
                            delta = chunk["choices"][0].get("delta", {})
                            if "content" in delta:
                                yield delta["content"]
                        except:
                            pass
