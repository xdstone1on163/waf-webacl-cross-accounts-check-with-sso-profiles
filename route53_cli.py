#!/usr/bin/env python3
"""
AWS Route53 多账户配置工具 - 统一 CLI 入口

提供子命令架构:
- scan: 扫描 Route53 Hosted Zones 和 DNS Records
- analyze: 分析 Route53 配置
- check-env: 检查环境配置
"""

import sys
import os
import argparse
import subprocess
import platform


def run_command(cmd: list, description: str) -> int:
    """
    运行子命令

    Args:
        cmd: 命令列表
        description: 命令描述

    Returns:
        返回码
    """
    try:
        # Windows 需要 shell=True
        use_shell = platform.system() == 'Windows'

        result = subprocess.run(
            cmd,
            shell=use_shell,
            check=False
        )
        return result.returncode
    except Exception as e:
        print(f"✗ {description} 失败: {str(e)}")
        return 1


def cmd_scan(args):
    """扫描 Route53 配置"""
    cmd = ['python3' if platform.system() != 'Windows' else 'python', 'get_route53_config.py']

    # 添加参数
    if args.profiles:
        cmd.extend(['-p'] + args.profiles)

    if args.regions:
        cmd.extend(['-r'] + args.regions)

    if args.output:
        cmd.extend(['-o', args.output])

    if args.debug:
        cmd.append('--debug')

    if args.no_parallel:
        cmd.append('--no-parallel')

    return run_command(cmd, "Route53 配置扫描")


def cmd_analyze(args):
    """分析 Route53 配置"""
    if not os.path.exists(args.json_file):
        print(f"✗ 文件不存在: {args.json_file}")
        return 1

    cmd = ['python3' if platform.system() != 'Windows' else 'python',
           'analyze_route53_config.py',
           args.json_file]

    # 添加分析选项
    if args.list:
        cmd.append('--list')

    if args.by_record_type:
        cmd.append('--by-record-type')

    if args.by_zone_type:
        cmd.append('--by-zone-type')

    if args.routing_policies:
        cmd.append('--routing-policies')

    if args.missing_health_checks:
        cmd.append('--missing-health-checks')

    if args.search:
        cmd.extend(['--search', args.search])

    if args.search_value:
        cmd.extend(['--search-value', args.search_value])

    if args.csv:
        cmd.extend(['--csv', args.csv])

    return run_command(cmd, "Route53 配置分析")


def cmd_check_env(args):
    """检查环境配置"""
    # 复用 WAF 工具的环境检查
    try:
        from core.waf_environment import EnvironmentChecker

        checker = EnvironmentChecker()
        checker.run_all_checks()  # 修复：使用 run_all_checks() 而非 check_all()
        return 0
    except ImportError:
        print("✗ 无法导入环境检查模块")
        print("提示: 确保 core/waf_environment.py 存在")
        return 1
    except Exception as e:
        print(f"✗ 环境检查失败: {str(e)}")
        return 1


def main():
    parser = argparse.ArgumentParser(
        description='AWS Route53 多账户配置工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例:
  # 扫描（使用配置文件）
  python route53_cli.py scan

  # 扫描指定账户
  python route53_cli.py scan -p profile1 profile2

  # 调试模式
  python route53_cli.py scan --debug

  # 禁用并行
  python route53_cli.py scan --no-parallel

  # 分析 - 列出所有 Zones
  python route53_cli.py analyze route53_config_*.json --list

  # 分析 - 按记录类型统计
  python route53_cli.py analyze route53_config_*.json --by-record-type

  # 分析 - 按 Zone 类型统计
  python route53_cli.py analyze route53_config_*.json --by-zone-type

  # 分析 - 路由策略统计
  python route53_cli.py analyze route53_config_*.json --routing-policies

  # 安全审计 - 查找缺少健康检查的记录
  python route53_cli.py analyze route53_config_*.json --missing-health-checks

  # 搜索 - 按名称
  python route53_cli.py analyze route53_config_*.json --search example.com

  # 搜索 - 按值（IP/CNAME 目标）
  python route53_cli.py analyze route53_config_*.json --search-value 192.0.2.1

  # 导出 CSV
  python route53_cli.py analyze route53_config_*.json --csv route53_report.csv

  # 环境检查
  python route53_cli.py check-env
        '''
    )

    subparsers = parser.add_subparsers(dest='command', help='子命令')

    # ========== scan 子命令 ==========
    scan_parser = subparsers.add_parser('scan', help='扫描 Route53 配置')

    scan_parser.add_argument('-p', '--profiles', nargs='+',
                            help='AWS SSO profile 名称列表')

    scan_parser.add_argument('-r', '--regions', nargs='+',
                            help='AWS 区域列表（Route53 是全局服务，此参数会被忽略但保留接口兼容性）')

    scan_parser.add_argument('-o', '--output',
                            help='输出文件路径')

    scan_parser.add_argument('--debug', action='store_true',
                            help='启用调试模式')

    scan_parser.add_argument('--no-parallel', action='store_true',
                            help='禁用并行扫描')

    # ========== analyze 子命令 ==========
    analyze_parser = subparsers.add_parser('analyze', help='分析 Route53 配置')

    analyze_parser.add_argument('json_file',
                               help='Route53 配置 JSON 文件路径')

    analyze_parser.add_argument('--list', action='store_true',
                               help='列出所有 Hosted Zones')

    analyze_parser.add_argument('--by-record-type', action='store_true',
                               help='按 DNS 记录类型统计')

    analyze_parser.add_argument('--by-zone-type', action='store_true',
                               help='按 Zone 类型统计（公有/私有）')

    analyze_parser.add_argument('--routing-policies', action='store_true',
                               help='分析路由策略使用情况')

    analyze_parser.add_argument('--missing-health-checks', action='store_true',
                               help='查找缺少健康检查的故障转移/加权记录（安全审计）')

    analyze_parser.add_argument('--search',
                               help='按 Zone 名称或记录名称搜索')

    analyze_parser.add_argument('--search-value',
                               help='按记录值搜索（IP 地址、CNAME 目标等）')

    analyze_parser.add_argument('--csv',
                               help='导出为 CSV 文件')

    # ========== check-env 子命令 ==========
    check_env_parser = subparsers.add_parser('check-env', help='检查环境配置')

    # 解析参数
    args = parser.parse_args()

    # 如果没有子命令，显示帮助
    if not args.command:
        parser.print_help()
        return 1

    # 执行对应的子命令
    if args.command == 'scan':
        return cmd_scan(args)
    elif args.command == 'analyze':
        return cmd_analyze(args)
    elif args.command == 'check-env':
        return cmd_check_env(args)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
