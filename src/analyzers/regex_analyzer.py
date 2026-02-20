"""
正则表达式分析器 - 优化版
改进：预编译正则表达式以提高性能
"""

import re
from typing import List, Dict, Tuple, Pattern
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


# 预编译所有正则表达式以提高性能
class CompiledPatterns:
    """预编译的正则表达式缓存"""

    def __init__(self):
        self._compiled: Dict[str, Pattern] = {}
        self._compile_all()

    def _compile_all(self):
        """编译所有模式"""
        # 字典类型的模式
        dict_patterns = [
            HIGH_RISK_PATTERNS,
            MEDIUM_RISK_PATTERNS,
            LOW_RISK_PATTERNS,
        ]

        for patterns in dict_patterns:
            for category, pattern_list in patterns.items():
                for pattern, description in pattern_list:
                    if pattern not in self._compiled:
                        try:
                            self._compiled[pattern] = re.compile(pattern, re.IGNORECASE)
                        except re.error:
                            # 如果编译失败，跳过
                            pass

        # 列表类型的模式 (SUSPICIOUS_PATTERNS)
        for pattern, description in SUSPICIOUS_PATTERNS:
            if pattern not in self._compiled:
                try:
                    self._compiled[pattern] = re.compile(pattern, re.IGNORECASE)
                except re.error:
                    pass

    def get(self, pattern: str) -> Pattern:
        """获取编译后的模式"""
        if pattern not in self._compiled:
            self._compiled[pattern] = re.compile(pattern, re.IGNORECASE)
        return self._compiled[pattern]


# 全局编译缓存
_compiled_cache = CompiledPatterns()


class RegexAnalyzer(BaseAnalyzer):
    """正则表达式分析器 - 快速模式匹配（优化版）"""

    def get_name(self) -> str:
        return "RegexAnalyzer"

    def _is_in_string_literal(self, content: str, position: int) -> bool:
        """检查位置是否在字符串字面量中 - 优化版"""
        # 只检查当前行，提高效率
        line_start = content.rfind('\n', 0, position) + 1
        line_end = content.find('\n', position)
        if line_end == -1:
            line_end = len(content)

        current_line = content[line_start:line_end]

        # 检查是否在字符串中（简化版，只检查双引号）
        quote_count = current_line.count('"')
        single_count = current_line.count("'")

        # 如果到 position 的引号数量是奇数，则在字符串中
        pos_in_line = position - line_start
        double_quotes_before = current_line[:pos_in_line].count('"')
        single_quotes_before = current_line[:pos_in_line].count("'")

        # 检查是否在引号对之间
        if double_quotes_before % 2 == 1:
            return True
        if single_quotes_before % 2 == 1:
            return True

        return False

    def _is_pattern_definition(self, content: str, position: int) -> bool:
        """检查是否是正则模式定义"""
        start = max(0, position - 100)
        end = min(len(content), position + 100)
        context = content[start:end]

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

    def _get_line_number(self, content: str, position: int) -> int:
        """获取位置对应的行号 - 优化版（使用快速计数）"""
        # 只计算到 position 的换行符数量
        return content.count('\n', 0, position) + 1

    def _check_patterns(
        self,
        content: str,
        patterns: Dict[str, List[Tuple[str, str]]],
        severity: Severity,
        file_path: Path
    ) -> List[SecurityIssue]:
        """检查模式 - 优化版"""
        issues = []
        relative_path = file_path.name

        for category, pattern_list in patterns.items():
            for pattern, description in pattern_list:
                try:
                    compiled = _compiled_cache.get(pattern)

                    for match in compiled.finditer(content):
                        pos = match.start()

                        # 跳过字符串字面量中的匹配
                        if self._is_in_string_literal(content, pos):
                            continue

                        # 跳过模式定义
                        if self._is_pattern_definition(content, pos):
                            continue

                        # 跳过示例代码
                        if self._is_example_code(content, pos):
                            continue

                        issues.append(SecurityIssue(
                            level=severity,
                            category=category,
                            description=description,
                            file=str(relative_path),
                            line=self._get_line_number(content, pos),
                            snippet=self._get_snippet(content, pos),
                            confidence=0.8
                        ))
                except re.error:
                    # 正则错误，跳过
                    continue

        return issues

    def analyze(self, file_path: Path, content: str) -> List[SecurityIssue]:
        """使用正则表达式分析文件 - 优化版"""
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
                try:
                    compiled = _compiled_cache.get(pattern)

                    for match in compiled.finditer(content):
                        url = match.group(0)
                        if self._is_safe_service(url):
                            continue

                        pos = match.start()

                        issues.append(SecurityIssue(
                            level=Severity.MEDIUM,
                            category='suspicious_url',
                            description=description,
                            file=str(file_path.name),
                            line=self._get_line_number(content, pos),
                            snippet=self._get_snippet(content, pos),
                            confidence=0.7
                        ))
                except re.error:
                    continue

        return issues
