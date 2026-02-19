"""
文本格式化器 - 带颜色和进度显示
"""

import sys
from typing import Optional

from .base import BaseFormatter
from ..types import ScanResult, SecurityIssue, Severity


class TextFormatter(BaseFormatter):
    """文本格式化器 - 带颜色输出"""
    
    # ANSI 颜色代码
    COLORS = {
        'RED': '\033[91m',
        'YELLOW': '\033[93m',
        'GREEN': '\033[92m',
        'BLUE': '\033[94m',
        'CYAN': '\033[96m',
        'MAGENTA': '\033[95m',
        'BOLD': '\033[1m',
        'RESET': '\033[0m'
    }
    
    # 风险等级图标
    ICONS = {
        Severity.HIGH: '🔴',
        Severity.MEDIUM: '🟡',
        Severity.LOW: '🟢',
        Severity.INFO: '🔵'
    }
    
    def __init__(self, use_color: bool = True):
        self.use_color = use_color and sys.stdout.isatty()
    
    def _color(self, text: str, color: str) -> str:
        """添加颜色"""
        if not self.use_color:
            return text
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['RESET']}"
    
    def get_name(self) -> str:
        return "TextFormatter"
    
    def format(self, result: ScanResult) -> str:
        """格式化扫描结果为文本"""
        lines = []
        
        # 标题
        lines.append(self._color("=" * 60, 'BOLD'))
        lines.append(self._color("🍊 ORANGE TRUSTSKILL - SECURITY SCAN REPORT", 'BOLD'))
        lines.append(self._color("=" * 60, 'BOLD'))
        
        # 扫描信息
        lines.append(f"\n📁 Skill: {result.skill_path}")
        lines.append(f"📄 Files Scanned: {result.files_scanned}")
        lines.append(f"⏱️  Scan Time: {result.scan_time:.2f}s")
        lines.append(f"🕐 Timestamp: {result.timestamp}")
        
        # 风险摘要
        summary = result.risk_summary
        lines.append(f"\n{self._color('📊 Risk Summary:', 'BOLD')}")
        lines.append(f"  {self.ICONS[Severity.HIGH]} {self._color('HIGH:', 'RED')}   {summary['HIGH']}")
        lines.append(f"  {self.ICONS[Severity.MEDIUM]} {self._color('MEDIUM:', 'YELLOW')} {summary['MEDIUM']}")
        lines.append(f"  {self.ICONS[Severity.LOW]} {self._color('LOW:', 'GREEN')}    {summary['LOW']}")
        if summary['INFO'] > 0:
            lines.append(f"  {self.ICONS[Severity.INFO]} INFO:   {summary['INFO']}")
        
        # 详细发现
        if result.findings:
            lines.append(f"\n{self._color('=' * 60, 'BOLD')}")
            lines.append(self._color("DETAILED FINDINGS", 'BOLD'))
            lines.append(self._color('=' * 60, 'BOLD'))
            
            for i, finding in enumerate(result.findings, 1):
                lines.append(self._format_finding(finding, i))
        else:
            lines.append(f"\n{self._color('✅ No security issues found!', 'GREEN')}")
        
        # 评估结果
        lines.append(f"\n{self._color('=' * 60, 'BOLD')}")
        lines.append(f"{self._color('Assessment:', 'BOLD')} {result.security_assessment}")
        lines.append(self._color('=' * 60, 'BOLD'))
        
        return '\n'.join(lines)
    
    def _format_finding(self, finding: SecurityIssue, index: int) -> str:
        """格式化单个发现"""
        lines = []
        icon = self.ICONS.get(finding.level, '⚪')
        
        # 等级颜色
        level_color = {
            Severity.HIGH: 'RED',
            Severity.MEDIUM: 'YELLOW',
            Severity.LOW: 'GREEN',
            Severity.INFO: 'BLUE'
        }.get(finding.level, 'RESET')
        
        lines.append(f"\n{icon} [{self._color(finding.level.value, level_color)}] {finding.category}")
        lines.append(f"   📄 File: {self._color(finding.file, 'CYAN')}:{finding.line}")
        lines.append(f"   📝 Issue: {finding.description}")
        if finding.confidence < 1.0:
            lines.append(f"   🎯 Confidence: {finding.confidence:.0%}")
        lines.append(f"   💻 Code: {self._color(finding.snippet, 'MAGENTA')}")
        lines.append("   " + "-" * 50)
        
        return '\n'.join(lines)


class ProgressTracker:
    """进度跟踪器"""
    
    def __init__(self, total: int, use_color: bool = True):
        self.total = total
        self.current = 0
        self.findings = 0
        self.use_color = use_color and sys.stdout.isatty()
    
    def update(self, filename: str, new_findings: int = 0):
        """更新进度"""
        self.current += 1
        self.findings += new_findings
        
        progress = (self.current / self.total) * 100
        bar_length = 30
        filled = int(bar_length * self.current / self.total)
        bar = '█' * filled + '░' * (bar_length - filled)
        
        color_start = '\033[92m' if self.use_color else ''
        color_end = '\033[0m' if self.use_color else ''
        
        status = f"\r{color_start}Scanning: [{bar}] {progress:.1f}% ({self.current}/{self.total}) | Issues: {self.findings}{color_end}"
        print(status, end='', flush=True)
    
    def finish(self):
        """完成进度"""
        print()  # 换行
