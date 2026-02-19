"""
AST 分析器 - Python 语法树分析
"""

import ast
import re
from typing import List, Optional, Dict, Any
from pathlib import Path

from .base import BaseAnalyzer
from ..types import SecurityIssue, Severity, AnalysisMode


class ASTAnalyzer(BaseAnalyzer):
    """AST 语法树分析器 - 深度代码分析"""
    
    def get_name(self) -> str:
        return "ASTAnalyzer"
    
    def analyze(self, file_path: Path, content: str) -> List[SecurityIssue]:
        """使用 AST 分析 Python 代码"""
        issues = []
        
        # 只分析 Python 文件
        if file_path.suffix != '.py':
            return issues
        
        try:
            tree = ast.parse(content)
            analyzer = PythonASTVisitor(content, str(file_path.name))
            analyzer.visit(tree)
            issues.extend(analyzer.issues)
        except SyntaxError:
            # 语法错误，跳过 AST 分析
            pass
        except Exception:
            # 其他错误，跳过
            pass
        
        return issues


class PythonASTVisitor(ast.NodeVisitor):
    """Python AST 访问器"""
    
    def __init__(self, content: str, filename: str):
        self.content = content
        self.filename = filename
        self.issues: List[SecurityIssue] = []
        self.lines = content.split('\n')
    
    def _get_line(self, node: ast.AST) -> int:
        """获取节点所在行号"""
        return getattr(node, 'lineno', 1)
    
    def _get_snippet(self, node: ast.AST, context: int = 50) -> str:
        """获取代码片段"""
        line_num = self._get_line(node)
        if 1 <= line_num <= len(self.lines):
            line = self.lines[line_num - 1].strip()
            return line[:100] + '...' if len(line) > 100 else line
        return ""
    
    def _is_dangerous_call(self, func_name: str) -> tuple:
        """检查是否是危险函数调用"""
        dangerous_funcs = {
            'eval': ('command_injection', 'eval() execution'),
            'exec': ('command_injection', 'exec() execution'),
            '__import__': ('dynamic_import', 'Dynamic import'),
            'compile': ('command_injection', 'compile() execution'),
        }
        return dangerous_funcs.get(func_name, None)
    
    def visit_Call(self, node: ast.Call):
        """访问函数调用"""
        func_name = self._get_func_name(node.func)
        
        if func_name:
            # 检查危险函数
            danger = self._is_dangerous_call(func_name)
            if danger:
                category, description = danger
                # 检查是否有变量参数（动态执行）
                has_variable = any(
                    not isinstance(arg, (ast.Constant, ast.Str))
                    for arg in node.args
                )
                
                if has_variable:
                    self.issues.append(SecurityIssue(
                        level=Severity.HIGH,
                        category=category,
                        description=f"{description} with variable",
                        file=self.filename,
                        line=self._get_line(node),
                        snippet=self._get_snippet(node),
                        confidence=0.9
                    ))
            
            # 检查 subprocess 调用
            if func_name in ['system', 'popen'] and self._is_os_call(node.func):
                self.issues.append(SecurityIssue(
                    level=Severity.HIGH,
                    category='command_injection',
                    description=f'os.{func_name}() call',
                    file=self.filename,
                    line=self._get_line(node),
                    snippet=self._get_snippet(node),
                    confidence=0.85
                ))
            
            # 检查 subprocess 带 shell=True
            if func_name in ['call', 'run', 'Popen'] and self._is_subprocess_call(node.func):
                if self._has_shell_true(node):
                    self.issues.append(SecurityIssue(
                        level=Severity.HIGH,
                        category='command_injection',
                        description='subprocess with shell=True',
                        file=self.filename,
                        line=self._get_line(node),
                        snippet=self._get_snippet(node),
                        confidence=0.95
                    ))
            
            # 检查 open() 调用
            if func_name == 'open':
                self._check_open_call(node)
        
        self.generic_visit(node)
    
    def visit_Import(self, node: ast.Import):
        """访问导入语句"""
        for alias in node.names:
            if alias.name in ['pickle', 'marshal', 'shelve']:
                self.issues.append(SecurityIssue(
                    level=Severity.MEDIUM,
                    category='deserialization',
                    description=f'{alias.name} import (unsafe deserialization)',
                    file=self.filename,
                    line=self._get_line(node),
                    snippet=self._get_snippet(node),
                    confidence=0.7
                ))
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        """访问 from ... import 语句"""
        if node.module == 'subprocess' and node.names:
            for alias in node.names:
                if alias.name in ['call', 'run', 'Popen', 'check_output']:
                    # 只是导入，不标记为问题，在使用时检查
                    pass
        
        if node.module in ['pickle', 'marshal']:
            self.issues.append(SecurityIssue(
                level=Severity.MEDIUM,
                category='deserialization',
                description=f'{node.module} import (unsafe deserialization)',
                file=self.filename,
                line=self._get_line(node),
                snippet=self._get_snippet(node),
                confidence=0.7
            ))
        
        self.generic_visit(node)
    
    def _get_func_name(self, node: ast.expr) -> Optional[str]:
        """获取函数名称"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return None
    
    def _is_os_call(self, node: ast.expr) -> bool:
        """检查是否是 os 模块调用"""
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return node.value.id == 'os'
        return False
    
    def _is_subprocess_call(self, node: ast.expr) -> bool:
        """检查是否是 subprocess 模块调用"""
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return node.value.id == 'subprocess'
        return False
    
    def _has_shell_true(self, node: ast.Call) -> bool:
        """检查是否有 shell=True 参数"""
        for keyword in node.keywords:
            if keyword.arg == 'shell':
                if isinstance(keyword.value, ast.Constant):
                    return keyword.value.value is True
                elif isinstance(keyword.value, ast.NameConstant):
                    return keyword.value.value is True
        return False
    
    def _check_open_call(self, node: ast.Call):
        """检查 open() 调用"""
        if not node.args:
            return
        
        first_arg = node.args[0]
        
        # 检查是否打开敏感文件
        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            filepath = first_arg.value
            sensitive_patterns = [
                (r'\.ssh[/\\]', 'SSH key access'),
                (r'password', 'Password file access'),
                (r'token', 'Token file access'),
                (r'secret', 'Secret file access'),
                (r'\.openclaw[/\\]config', 'OpenClaw config access'),
                (r'MEMORY\.md|SOUL\.md|USER\.md', 'Memory file access'),
            ]
            
            for pattern, description in sensitive_patterns:
                if re.search(pattern, filepath, re.IGNORECASE):
                    self.issues.append(SecurityIssue(
                        level=Severity.HIGH,
                        category='sensitive_file_access',
                        description=description,
                        file=self.filename,
                        line=self._get_line(node),
                        snippet=self._get_snippet(node),
                        confidence=0.85
                    ))
                    break
