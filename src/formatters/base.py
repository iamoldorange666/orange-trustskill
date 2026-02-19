"""
输出格式化器基类
"""

from abc import ABC, abstractmethod
from typing import Dict, Any

from ..types import ScanResult


class BaseFormatter(ABC):
    """格式化器基类"""
    
    @abstractmethod
    def format(self, result: ScanResult) -> str:
        """
        格式化扫描结果
        
        Args:
            result: 扫描结果
            
        Returns:
            格式化后的字符串
        """
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """获取格式化器名称"""
        pass
