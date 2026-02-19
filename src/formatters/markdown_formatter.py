"""
Markdown 格式化器 - 用于 LLM 审查
"""

from .base import BaseFormatter
from ..types import ScanResult, Severity


class MarkdownFormatter(BaseFormatter):
    """Markdown 格式化器 - 导出给 LLM 审查"""
    
    def get_name(self) -> str:
        return "MarkdownFormatter"
    
    def format(self, result: ScanResult) -> str:
        """格式化扫描结果为 Markdown"""
        lines = [
            "# 🔒 Orange TrustSkill - Security Scan Report",
            "",
            "---",
            "",
            "## 📋 Scan Information",
            "",
            f"- **Skill Path**: `{result.skill_path}`",
            f"- **Files Scanned**: {result.files_scanned}",
            f"- **Scan Time**: {result.scan_time:.2f}s",
            f"- **Timestamp**: {result.timestamp}",
            "",
            "---",
            "",
            "## 📊 Risk Summary",
            "",
            "| Level | Count |",
            "|-------|-------|",
            f"| 🔴 HIGH | {result.risk_summary['HIGH']} |",
            f"| 🟡 MEDIUM | {result.risk_summary['MEDIUM']} |",
            f"| 🟢 LOW | {result.risk_summary['LOW']} |",
            "",
            "---",
            "",
        ]
        
        if result.findings:
            lines.extend([
                "## 🚨 Detailed Findings",
                "",
            ])
            
            for finding in result.findings:
                icon = {
                    Severity.HIGH: '🔴',
                    Severity.MEDIUM: '🟡',
                    Severity.LOW: '🟢',
                    Severity.INFO: '🔵'
                }.get(finding.level, '⚪')
                
                lines.extend([
                    f"### {icon} [{finding.level.value}] {finding.category}",
                    "",
                    f"- **File**: `{finding.file}:{finding.line}`",
                    f"- **Issue**: {finding.description}",
                    f"- **Confidence**: {finding.confidence:.0%}",
                    "",
                    "**Code Snippet**:",
                    "```",
                    finding.snippet,
                    "```",
                    "",
                    "---",
                    "",
                ])
        else:
            lines.extend([
                "## ✅ Result",
                "",
                "No security issues found.",
                "",
                "---",
                "",
            ])
        
        lines.extend([
            "## 📝 Assessment",
            "",
            result.security_assessment,
            "",
            "---",
            "",
        ])
        
        return '\n'.join(lines)
