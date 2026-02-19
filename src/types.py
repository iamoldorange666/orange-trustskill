"""
Orange TrustSkill v2.0 - Advanced Security Scanner
Enhanced version with AST analysis, multi-format output, and progress tracking
"""

from enum import Enum, auto
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime


class Severity(Enum):
    """风险等级"""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM" 
    LOW = "LOW"
    INFO = "INFO"


class AnalysisMode(Enum):
    """分析模式"""
    FAST = "fast"           # 仅正则
    STANDARD = "standard"   # 正则 + AST
    DEEP = "deep"           # 正则 + AST + 深度检查


@dataclass
class SecurityIssue:
    """安全问题"""
    level: Severity
    category: str
    description: str
    file: str
    line: int
    snippet: str
    confidence: float = 1.0  # 置信度 0-1
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "category": self.category,
            "description": self.description,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "confidence": self.confidence
        }


@dataclass
class ScanResult:
    """扫描结果"""
    skill_path: str
    files_scanned: int
    findings: List[SecurityIssue]
    scan_time: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    @property
    def risk_summary(self) -> Dict[str, int]:
        summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in self.findings:
            summary[finding.level.value] += 1
        return summary
    
    @property
    def security_assessment(self) -> str:
        summary = self.risk_summary
        if summary["HIGH"] > 0:
            return "🔴 CRITICAL: High-risk issues detected. Manual review required."
        elif summary["MEDIUM"] > 5:
            return "🟡 WARNING: Multiple medium-risk issues found. Review recommended."
        elif summary["MEDIUM"] > 0:
            return "🟢 CAUTION: Some medium-risk issues found. Review suggested."
        else:
            return "✅ SAFE: No significant security issues found."
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "skill_path": self.skill_path,
            "files_scanned": self.files_scanned,
            "findings": [f.to_dict() for f in self.findings],
            "risk_summary": self.risk_summary,
            "security_assessment": self.security_assessment,
            "scan_time": self.scan_time,
            "timestamp": self.timestamp
        }
