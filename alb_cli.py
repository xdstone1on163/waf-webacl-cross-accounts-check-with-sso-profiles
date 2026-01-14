#!/usr/bin/env python3
"""
AWS ALB 多账户配置工具 - 统一 CLI 入口

提供子命令架构:
- scan: 扫描 ALB 配置
- analyze: 分析 ALB 配置
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
    """扫描 ALB 配置"""
    cmd = ['python3' if platform.system() != 'Windows' else 'python', 'get_alb_config.py']

    # 添加参数
    if args.profiles:
        cmd.extend(['-p'] + args.profiles)

    if args.regions:
        cmd.extend(['-r'] + args.regions)

    if args.mode:
        cmd.extend(['--mode', args.mode])

    if args.output:
        cmd.extend(['-o', args.output])

    if args.debug:
        cmd.append('--debug')

    if args.no_parallel:
        cmd.append('--no-parallel')

    return run_command(cmd, "ALB 配置扫描")


def cmd_analyze(args):
    """分析 ALB 配置"""
    if not os.path.exists(args.json_file):
        print(f"✗ 文件不存在: {args.json_file}")
        return 1

    cmd = ['python3' if platform.system() != 'Windows' else 'python',
           'analyze_alb_config.py',
           args.json_file]

    # 添加分析选项
    if args.list:
        cmd.append('--list')

    if args.waf_coverage:
        cmd.append('--waf-coverage')

    if args.no_waf:
        cmd.append('--no-waf')

    if args.by_type:
        cmd.append('--by-type')

    if args.by_region:
        cmd.append('--by-region')

    if args.search:
        cmd.extend(['--search', args.search])

    if args.csv:
        cmd.extend(['--csv', args.csv])

    return run_command(cmd, "ALB 配置分析")


def cmd_check_env(args):
    """检查环境配置"""
    # 复用 WAF 工具的环境检查
    try:
        from core.waf_environment import EnvironmentChecker

        checker = EnvironmentChecker()
        checker.check_all()
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
        description='AWS ALB 多账户配置工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例:
  # 交互式扫描（推荐）
  python alb_cli.py scan --interactive

  # 快速扫描
  python alb_cli.py scan --mode quick

  # 标准扫描（默认）
  python alb_cli.py scan -p profile1 profile2

  # 完整扫描（包含健康检查）
  python alb_cli.py scan --mode full

  # 分析结果
  python alb_cli.py analyze alb_config_*.json --list
  python alb_cli.py analyze alb_config_*.json --waf-coverage
  python alb_cli.py analyze alb_config_*.json --no-waf

  # 环境检查
  python alb_cli.py check-env
        '''
    )

    subparsers = parser.add_subparsers(dest='command', help='子命令')

    # ========== scan 子命令 ==========
    scan_parser = subparsers.add_parser('scan', help='扫描 ALB 配置')

    scan_parser.add_argument('--interactive', '-i', action='store_true',
                            help='交互式模式（暂未实现）')

    scan_parser.add_argument('-p', '--profiles', nargs='+',
                            help='AWS SSO profile 名称列表')

    scan_parser.add_argument('-r', '--regions', nargs='+',
                            help='要扫描的 AWS 区域列表')

    scan_parser.add_argument('--mode', choices=['quick', 'standard', 'full'],
                            default='standard',
                            help='扫描模式 (quick: 基本+WAF, standard: +监听器+目标组, full: +规则+健康检查)')

    scan_parser.add_argument('-o', '--output',
                            help='输出文件路径')

    scan_parser.add_argument('--debug', action='store_true',
                            help='启用调试模式')

    scan_parser.add_argument('--no-parallel', action='store_true',
                            help='禁用并行扫描')

    # ========== analyze 子命令 ==========
    analyze_parser = subparsers.add_parser('analyze', help='分析 ALB 配置')

    analyze_parser.add_argument('json_file',
                               help='ALB 配置 JSON 文件路径')

    analyze_parser.add_argument('--list', action='store_true',
                               help='列出所有 ALB')

    analyze_parser.add_argument('--waf-coverage', action='store_true',
                               help='分析 WAF 覆盖率')

    analyze_parser.add_argument('--no-waf', action='store_true',
                               help='列出未绑定 WAF 的 ALB')

    analyze_parser.add_argument('--by-type', action='store_true',
                               help='按类型统计（ALB/NLB/GLB）')

    analyze_parser.add_argument('--by-region', action='store_true',
                               help='按区域统计')

    analyze_parser.add_argument('--search',
                               help='搜索指定名称的 ALB')

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
        if args.interactive:
            print("⚠️  交互式模式暂未实现，请使用命令行参数")
            return 1
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
