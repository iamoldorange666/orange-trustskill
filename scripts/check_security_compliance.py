#!/usr/bin/env python3
"""
Orange TrustSkill - SECURITY.md Compliance Checker
检查 Agent 是否正确引用 SECURITY.md
Author: orange
Version: 1.2.0
"""

import os
import sys
from pathlib import Path


def check_security_md_reference(soul_md_path: str) -> dict:
    """
    检查 SOUL.md 是否正确引用 SECURITY.md
    
    Returns:
        {
            'has_reference': bool,
            'security_md_exists': bool,
            'issues': list,
            'score': int  # 0-100
        }
    """
    result = {
        'has_reference': False,
        'security_md_exists': False,
        'issues': [],
        'score': 0
    }
    
    # 检查 SECURITY.md 是否存在
    security_md = os.path.expanduser("~/.openclaw/workspace/SECURITY.md")
    result['security_md_exists'] = os.path.exists(security_md)
    
    if not result['security_md_exists']:
        result['issues'].append("SECURITY.md 不存在")
        return result
    
    # 检查 SOUL.md 是否引用 SECURITY.md
    if not os.path.exists(soul_md_path):
        result['issues'].append(f"SOUL.md 不存在: {soul_md_path}")
        return result
    
    try:
        with open(soul_md_path, 'r', encoding='utf-8') as f:
            content = f.read().lower()
            
        # 检查关键标识
        checks = {
            '引用 security.md': 'security.md' in content,
            '安全基线章节': '安全基线' in content or 'security' in content,
            '外部内容不可信': '外部内容' in content,
            '敏感操作确认': '敏感操作' in content or '人工确认' in content,
            '密钥保护': '密钥' in content or 'api key' in content,
            '行为准则': '宁可漏做' in content or '不可错做' in content
        }
        
        passed = sum(checks.values())
        total = len(checks)
        result['score'] = int((passed / total) * 100)
        
        for check_name, passed_check in checks.items():
            if not passed_check:
                result['issues'].append(f"缺少: {check_name}")
        
        result['has_reference'] = checks['引用 security.md'] and result['score'] >= 50
        
    except Exception as e:
        result['issues'].append(f"读取文件失败: {e}")
    
    return result


def check_all_agents():
    """检查所有 Agent 的合规性"""
    workspace = os.path.expanduser("~/.openclaw/workspace")
    agents_to_check = [
        ("小橘子 (主Agent)", os.path.join(workspace, "SOUL.md")),
        ("小红薯 (子Agent)", os.path.join(workspace, "subagents", "小红薯", "SOUL.md"))
    ]
    
    print("🛡️  SECURITY.md 合规检查")
    print("=" * 60)
    
    all_passed = True
    
    for agent_name, soul_path in agents_to_check:
        print(f"\n📋 检查: {agent_name}")
        print(f"   路径: {soul_path}")
        
        result = check_security_md_reference(soul_path)
        
        if result['security_md_exists']:
            print(f"   ✅ SECURITY.md 存在")
        else:
            print(f"   ❌ SECURITY.md 不存在")
            all_passed = False
        
        if result['has_reference']:
            print(f"   ✅ 已正确引用 SECURITY.md")
        else:
            print(f"   ❌ 未引用或引用不完整 SECURITY.md")
            all_passed = False
        
        print(f"   📊 合规评分: {result['score']}/100")
        
        if result['issues']:
            print(f"   ⚠️  问题:")
            for issue in result['issues']:
                print(f"      - {issue}")
        else:
            print(f"   ✅ 无问题")
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✅ 所有 Agent 合规！")
    else:
        print("⚠️  部分 Agent 需要更新安全基线引用")
    
    return all_passed


if __name__ == "__main__":
    # 如果带参数，检查指定文件
    if len(sys.argv) > 1:
        soul_md = sys.argv[1]
        result = check_security_md_reference(soul_md)
        print(f"\n检查: {soul_md}")
        print(f"SECURITY.md 存在: {result['security_md_exists']}")
        print(f"已引用: {result['has_reference']}")
        print(f"评分: {result['score']}/100")
        if result['issues']:
            print("问题:")
            for issue in result['issues']:
                print(f"  - {issue}")
    else:
        # 检查所有 Agent
        check_all_agents()
