"""
基础分析器类
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from pathlib import Path

from ..types import SecurityIssue, AnalysisMode


class BaseAnalyzer(ABC):
    """分析器基类"""
    
    def __init__(self, mode: AnalysisMode = AnalysisMode.STANDARD):
        self.mode = mode
    
    @abstractmethod
    def analyze(self, file_path: Path, content: str) -> List[SecurityIssue]:
        """
        分析文件内容
        
        Args:
            file_path: 文件路径
            content: 文件内容
            
        Returns:
            发现的安全问题列表
        """
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """获取分析器名称"""
        pass
