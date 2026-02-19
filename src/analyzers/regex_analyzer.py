"""
正则表达式分析器
"""

import re
from typing import List
from pathlib import Path

from .base import BaseAnalyzer
from ..types import SecurityIssue, Severity, AnalysisMode
from ..rules import (
    HIGH_RISK_PATTERNS, 
    MEDIUM_RISK_PATTERNS, 
    LOW_RISK_PATTERNS,
    SUSPICIOUS_PATTERNS,
    SAFE_SERVICES
)


class RegexAnalyzer(BaseAnalyzer):
    """正则表达式分析器 - 快速模式匹配"""
    
    def get_name(self) -> str:
        return "RegexAnalyzer"
    
    def _is_in_string_literal(self, content: str, position: int) -> bool:
        """检查位置是否在字符串字面量中"""
        lines_before = content[:position].split('\n')
        current_line = lines_before[-1] if lines_before else ""
        
        single_quotes = current_line.count("'") - current_line.count("\'")
        double_quotes = current_line.count('"') - current_line.count('\"')
        
        return (single_quotes % 2 == 1 or double_quotes % 2 == 1)
    
    def _is_pattern_definition(self, content: str, position: int) -> bool:
        """检查是否是正则模式定义"""
        context = content[max(0, position-100):position+100]
        indicators = [
            "PATTERNS", "patterns", "regex", "PATTERN", 
            "r'", 'r"', "re.compile", ".compile("
        ]
        return any(ind in context for ind in indicators)
    
    def _is_example_code(self, content: str, position: int) -> bool:
        """检查是否是示例/文档代码"""
        start = max(0, position - 200)
        end = min(len(content), position + 200)
        context = content[start:end].lower()
        
        indicators = [
            'example', 'danger:', 'caution:', 'warning:', 
            'bad:', 'wrong:', 'unsafe:', 'risk:', 'pattern',
            'todo:', 'note:', 'security notice'
        ]
        return any(ind in context for ind in indicators)
    
    def _is_safe_service(self, url: str) -> bool:
        """检查是否是安全服务"""
        return any(service in url for service in SAFE_SERVICES)
    
    def _get_snippet(self, content: str, position: int, context: int = 50) -> str:
        """获取代码片段"""
        start = max(0, position - context)
        end = min(len(content), position + context)
        snippet = content[start:end].replace('\n', ' ').strip()
        return snippet[:100] + '...' if len(snippet) > 100 else snippet
    
    def _check_patterns(
        self, 
        content: str, 
        patterns: dict, 
        severity: Severity,
        file_path: Path
    ) -> List[SecurityIssue]:
        """检查模式"""
        issues = []
        relative_path = file_path.name
        
        for category, pattern_list in patterns.items():
            for pattern, description in pattern_list:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    pos = match.start()
                    
                    # 跳过字符串字面量中的匹配（可能是正则定义）
                    if self._is_in_string_literal(content, pos):
                        continue
                    
                    # 跳过模式定义
                    if self._is_pattern_definition(content, pos):
                        continue
                    
                    # 跳过示例代码
                    if self._is_example_code(content, pos):
                        continue
                    
                    line_num = content[:pos].count('\n') + 1
                    
                    issues.append(SecurityIssue(
                        level=severity,
                        category=category,
                        description=description,
                        file=str(relative_path),
                        line=line_num,
                        snippet=self._get_snippet(content, pos),
                        confidence=0.8
                    ))
        
        return issues
    
    def analyze(self, file_path: Path, content: str) -> List[SecurityIssue]:
        """使用正则表达式分析文件"""
        issues = []
        
        # 检查高风险模式
        issues.extend(self._check_patterns(
            content, HIGH_RISK_PATTERNS, Severity.HIGH, file_path
        ))
        
        # 检查中风险模式
        if self.mode in [AnalysisMode.STANDARD, AnalysisMode.DEEP]:
            issues.extend(self._check_patterns(
                content, MEDIUM_RISK_PATTERNS, Severity.MEDIUM, file_path
            ))
        
        # 检查低风险模式
        if self.mode == AnalysisMode.DEEP:
            issues.extend(self._check_patterns(
                content, LOW_RISK_PATTERNS, Severity.LOW, file_path
            ))
        
        # 检查可疑 URL
        if self.mode in [AnalysisMode.STANDARD, AnalysisMode.DEEP]:
            for pattern, description in SUSPICIOUS_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    url = match.group(0)
                    if self._is_safe_service(url):
                        continue
                    
                    pos = match.start()
                    line_num = content[:pos].count('\n') + 1
                    
                    issues.append(SecurityIssue(
                        level=Severity.MEDIUM,
                        category='suspicious_url',
                        description=description,
                        file=str(file_path.name),
                        line=line_num,
                        snippet=self._get_snippet(content, pos),
                        confidence=0.7
                    ))
        
        return issues
