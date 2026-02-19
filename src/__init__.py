"""
Orange TrustSkill v2.0
Advanced Security Scanner for OpenClaw Skills
"""

__version__ = "2.0.0"
__author__ = "Orange"
__description__ = "Advanced security scanner with AST analysis"

from .types import (
    Severity,
    AnalysisMode,
    SecurityIssue,
    ScanResult
)
from .scanner import SkillScanner
from .analyzers.regex_analyzer import RegexAnalyzer
from .analyzers.ast_analyzer import ASTAnalyzer
from .formatters.text_formatter import TextFormatter, ProgressTracker
from .formatters.json_formatter import JsonFormatter
from .formatters.markdown_formatter import MarkdownFormatter

__all__ = [
    '__version__',
    'Severity',
    'AnalysisMode',
    'SecurityIssue',
    'ScanResult',
    'SkillScanner',
    'RegexAnalyzer',
    'ASTAnalyzer',
    'TextFormatter',
    'ProgressTracker',
    'JsonFormatter',
    'MarkdownFormatter',
]
