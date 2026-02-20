"""
主扫描器 - 整合所有分析器
优化版本：添加文件大小限制和更好的错误处理
"""

import time
from pathlib import Path
from typing import List, Optional, Type, Callable

from .types import ScanResult, SecurityIssue, AnalysisMode
from .analyzers.base import BaseAnalyzer
from .analyzers.regex_analyzer import RegexAnalyzer
from .analyzers.ast_analyzer import ASTAnalyzer
from .rules import SCAN_EXTENSIONS, IGNORE_PATTERNS
import re
import fnmatch


class SkillScanner:
    """Skill 安全扫描器 - 主类"""

    # 最大文件大小：10MB（防止扫描超大文件导致内存问题）
    MAX_FILE_SIZE = 10 * 1024 * 1024

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
        """检查是否应该忽略该路径 - 优化版使用 fnmatch"""
        path_str = str(path)
        path_parts = path_str.split('/')

        for pattern in IGNORE_PATTERNS:
            # 检查路径的任何部分是否匹配
            for part in path_parts:
                if fnmatch.fnmatch(part, pattern):
                    return True
            # 也检查完整路径
            if re.search(pattern, path_str):
                return True
        return False

    def _get_files_to_scan(self, skill_path: Path) -> List[Path]:
        """获取要扫描的文件列表 - 优化版"""
        files = []

        # 递归遍历目录
        try:
            for item in skill_path.rglob('*'):
                if not item.is_file():
                    continue

                # 检查是否在忽略列表
                if self._should_ignore(item):
                    continue

                # 检查文件大小
                try:
                    if item.stat().st_size > self.MAX_FILE_SIZE:
                        continue
                except (OSError, IOError):
                    continue

                # 检查扩展名
                if item.suffix in SCAN_EXTENSIONS:
                    files.append(item)
        except (PermissionError, OSError):
            # 目录无法访问，返回空列表
            pass

        # 确保包含 SKILL.md
        skill_md = skill_path / 'SKILL.md'
        if skill_md.exists() and skill_md not in files:
            try:
                if skill_md.stat().st_size <= self.MAX_FILE_SIZE:
                    files.append(skill_md)
            except (OSError, IOError):
                pass

        return sorted(set(files))  # 去重并排序

    def scan(
        self,
        skill_path: str,
        progress_callback: Optional[Callable] = None
    ) -> ScanResult:
        """
        扫描 skill - 优化版

        Args:
            skill_path: skill 目录路径
            progress_callback: 进度回调函数 (filename, current, total, findings)

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
                # 读取文件内容（带大小限制检查）
                try:
                    file_size = file_path.stat().st_size
                    if file_size > self.MAX_FILE_SIZE:
                        continue
                except (OSError, IOError):
                    continue

                content = file_path.read_text(encoding='utf-8', errors='ignore')
            except (OSError, IOError, UnicodeDecodeError):
                continue
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
                try:
                    progress_callback(
                        file_path.name,
                        files_scanned,
                        total_files,
                        len(all_findings)
                    )
                except Exception:
                    # 回调出错，忽略
                    pass

        scan_time = time.time() - start_time

        return ScanResult(
            skill_path=str(skill_path),
            files_scanned=files_scanned,
            findings=all_findings,
            scan_time=scan_time
        )
