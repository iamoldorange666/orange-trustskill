#!/bin/bash
# Orange TrustSkill v2.0 - 兼容旧版本的入口脚本
# 这个脚本为了兼容 v1.x 的调用方式

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "${SCRIPT_DIR}/../src/cli.py" "$@"
