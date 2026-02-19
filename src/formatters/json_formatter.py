"""
JSON 格式化器
"""

import json
from typing import Dict, Any

from .base import BaseFormatter
from ..types import ScanResult


class JsonFormatter(BaseFormatter):
    """JSON 格式化器"""
    
    def __init__(self, indent: int = 2):
        self.indent = indent
    
    def get_name(self) -> str:
        return "JsonFormatter"
    
    def format(self, result: ScanResult) -> str:
        """格式化扫描结果为 JSON"""
        return json.dumps(result.to_dict(), indent=self.indent, ensure_ascii=False)
