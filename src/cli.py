#!/usr/bin/env python3
"""
Orange TrustSkill v2.0 - 主入口脚本
Advanced Security Scanner for OpenClaw Skills
"""

import sys
import argparse
from pathlib import Path

# 添加 src 到路径
script_dir = Path(__file__).parent
sys.path.insert(0, str(script_dir))
sys.path.insert(0, str(script_dir.parent))

try:
    from src.types import AnalysisMode
    from src.scanner import SkillScanner
    from src.formatters.text_formatter import TextFormatter, ProgressTracker
    from src.formatters.json_formatter import JsonFormatter
    from src.formatters.markdown_formatter import MarkdownFormatter
except ImportError:
    # 如果 src 导入失败，尝试直接导入
    from types import AnalysisMode
    from scanner import SkillScanner
    from formatters.text_formatter import TextFormatter, ProgressTracker
    from formatters.json_formatter import JsonFormatter
    from formatters.markdown_formatter import MarkdownFormatter


def main():
    parser = argparse.ArgumentParser(
        description='🍊 Orange TrustSkill v2.0 - Security Scanner for OpenClaw Skills',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/skill
  %(prog)s /path/to/skill --mode deep
  %(prog)s /path/to/skill --format json
  %(prog)s /path/to/skill --export-for-llm
        """
    )
    
    parser.add_argument(
        'skill_path',
        help='Path to skill directory to scan'
    )
    
    parser.add_argument(
        '-m', '--mode',
        choices=['fast', 'standard', 'deep'],
        default='standard',
        help='Analysis mode (default: standard)'
    )
    
    parser.add_argument(
        '-f', '--format',
        choices=['text', 'json', 'markdown'],
        default='text',
        help='Output format (default: text)'
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    parser.add_argument(
        '--no-progress',
        action='store_true',
        help='Disable progress bar'
    )
    
    parser.add_argument(
        '--export-for-llm',
        action='store_true',
        help='Export as Markdown for LLM review (same as --format markdown)'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode, only show summary'
    )
    
    parser.add_argument(
        '-v', '--version',
        action='version',
        version='%(prog)s 2.0.0'
    )
    
    args = parser.parse_args()
    
    # 处理 export-for-llm
    if args.export_for_llm:
        args.format = 'markdown'
    
    # 转换 mode
    mode_map = {
        'fast': AnalysisMode.FAST,
        'standard': AnalysisMode.STANDARD,
        'deep': AnalysisMode.DEEP
    }
    mode = mode_map[args.mode]
    
    # 创建扫描器
    scanner = SkillScanner(mode=mode)
    
    # 创建进度跟踪器
    progress = None
    if not args.no_progress and args.format == 'text' and not args.quiet:
        # 先获取文件总数
        from src.rules import SCAN_EXTENSIONS, IGNORE_PATTERNS
        import re
        
        skill_path = Path(args.skill_path)
        total_files = 0
        if skill_path.exists():
            for item in skill_path.rglob('*'):
                if item.is_file():
                    path_str = str(item)
                    should_ignore = any(re.search(p, path_str) for p in IGNORE_PATTERNS)
                    if not should_ignore and item.suffix in SCAN_EXTENSIONS:
                        total_files += 1
        
        if total_files > 0:
            progress = ProgressTracker(total_files, use_color=not args.no_color)
    
    # 扫描
    def progress_callback(filename: str, current: int, total: int, findings: int):
        if progress:
            progress.update(filename, 0)
    
    result = scanner.scan(args.skill_path, progress_callback if progress else None)
    
    if progress:
        progress.finish()
    
    # 格式化输出
    if args.format == 'json':
        formatter = JsonFormatter()
    elif args.format == 'markdown':
        formatter = MarkdownFormatter()
    else:
        formatter = TextFormatter(use_color=not args.no_color)
    
    output = formatter.format(result)
    print(output)
    
    # 退出码
    if result.risk_summary['HIGH'] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
