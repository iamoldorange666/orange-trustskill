"""
主扫描器 - 整合所有分析器
"""

import time
from pathlib import Path
from typing import List, Optional, Type

from .types import ScanResult, SecurityIssue, AnalysisMode
from .analyzers.base import BaseAnalyzer
from .analyzers.regex_analyzer import RegexAnalyzer
from .analyzers.ast_analyzer import ASTAnalyzer
from .rules import SCAN_EXTENSIONS, IGNORE_PATTERNS
import re


class SkillScanner:
    """Skill 安全扫描器 - 主类"""
    
    def __init__(self, mode: AnalysisMode = AnalysisMode.STANDARD):
        """
        初始化扫描器
        
        Args:
            mode: 分析模式
        """
        self.mode = mode
        self.analyzers = self._init_analyzers()
    
    def _init_analyzers(self) -> List[BaseAnalyzer]:
        """初始化分析器列表"""
        analyzers = []
        
        # 所有模式都包含正则分析
        analyzers.append(RegexAnalyzer(self.mode))
        
        # STANDARD 和 DEEP 模式包含 AST 分析
        if self.mode in [AnalysisMode.STANDARD, AnalysisMode.DEEP]:
            analyzers.append(ASTAnalyzer(self.mode))
        
        return analyzers
    
    def _should_ignore(self, path: Path) -> bool:
        """检查是否应该忽略该路径"""
        path_str = str(path)
        for pattern in IGNORE_PATTERNS:
            if re.search(pattern, path_str):
                return True
        return False
    
    def _get_files_to_scan(self, skill_path: Path) -> List[Path]:
        """获取要扫描的文件列表"""
        files = []
        
        # 递归遍历目录
        for item in skill_path.rglob('*'):
            if item.is_file():
                # 检查是否在忽略列表
                if self._should_ignore(item):
                    continue
                
                # 检查扩展名
                if item.suffix in SCAN_EXTENSIONS:
                    files.append(item)
        
        # 确保包含 SKILL.md
        skill_md = skill_path / 'SKILL.md'
        if skill_md.exists() and skill_md not in files:
            files.append(skill_md)
        
        return sorted(set(files))  # 去重并排序
    
    def scan(
        self, 
        skill_path: str,
        progress_callback: Optional[callable] = None
    ) -> ScanResult:
        """
        扫描 skill
        
        Args:
            skill_path: skill 目录路径
            progress_callback: 进度回调函数 (current, total, findings)
            
        Returns:
            扫描结果
        """
        start_time = time.time()
        skill_path = Path(skill_path)
        
        if not skill_path.exists():
            return ScanResult(
                skill_path=str(skill_path),
                files_scanned=0,
                findings=[],
                scan_time=0,
                timestamp=""
            )
        
        # 获取文件列表
        files = self._get_files_to_scan(skill_path)
        total_files = len(files)
        
        all_findings: List[SecurityIssue] = []
        files_scanned = 0
        
        # 扫描每个文件
        for file_path in files:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                continue
            
            file_findings = []
            
            # 使用所有分析器
            for analyzer in self.analyzers:
                try:
                    findings = analyzer.analyze(file_path, content)
                    file_findings.extend(findings)
                except Exception:
                    # 分析器出错，继续下一个
                    continue
            
            all_findings.extend(file_findings)
            files_scanned += 1
            
            # 回调进度
            if progress_callback:
                progress_callback(
                    file_path.name,
                    files_scanned,
                    total_files,
                    len(all_findings)
                )
        
        scan_time = time.time() - start_time
        
        return ScanResult(
            skill_path=str(skill_path),
            files_scanned=files_scanned,
            findings=all_findings,
            scan_time=scan_time
        )
