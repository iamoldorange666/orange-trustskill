#!/usr/bin/env python3
"""
Orange TrustSkill v2.0 - 兼容旧版本的 Python 入口
为了保持向后兼容，这个脚本提供 v1.x 的调用接口
"""

import sys
import os

# 获取脚本所在目录
script_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(os.path.dirname(script_dir), 'src')

# 添加到路径
sys.path.insert(0, src_dir)
sys.path.insert(0, os.path.dirname(src_dir))

# 导入 v2 的 CLI
from src.cli import main

if __name__ == '__main__':
    main()
