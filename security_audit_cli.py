#!/usr/bin/env python3
"""
AWS Security Audit CLI

命令行接口，用于生成安全配置关联分析和可视化报告。
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

# 导入关联分析器和可视化生成器
try:
    from correlate_security_config import SecurityConfigCorrelator
    from security_visualizer import SecurityVisualizer
except ImportError as e:
    print(f"✗ Error: Failed to import required modules: {e}", file=sys.stderr)
    print("  Please ensure all required files are in the same directory", file=sys.stderr)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='AWS Security Configuration Correlation and Visualization Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Generate report from scan results
  python security_audit_cli.py correlate waf_config.json alb_config.json route53_config.json

  # Specify output filename
  python security_audit_cli.py correlate waf_config.json alb_config.json route53_config.json -o report.html

  # Save JSON data for debugging
  python security_audit_cli.py correlate waf_config.json alb_config.json route53_config.json --json --debug

  # Check environment
  python security_audit_cli.py check-env
        '''
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # correlate 子命令
    correlate_parser = subparsers.add_parser(
        'correlate',
        help='Correlate and visualize security configurations'
    )
    correlate_parser.add_argument('waf_json', nargs='?', help='WAF configuration JSON file')
    correlate_parser.add_argument('alb_json', nargs='?', help='ALB configuration JSON file')
    correlate_parser.add_argument('route53_json', nargs='?', help='Route53 configuration JSON file')
    correlate_parser.add_argument(
        '--use-latest',
        action='store_true',
        help='自动使用 *_latest.json 文件（无需手动指定文件名）'
    )
    correlate_parser.add_argument(
        '-o', '--output',
        help='Output HTML file (default: security_audit_report_YYYYMMDD_HHMMSS.html)',
        default=None
    )
    correlate_parser.add_argument(
        '--json',
        action='store_true',
        help='Also output JSON data file (for debugging)'
    )
    correlate_parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )

    # check-env 子命令
    check_env_parser = subparsers.add_parser(
        'check-env',
        help='Check environment prerequisites'
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # 执行相应的命令
    if args.command == 'correlate':
        run_correlate(args)
    elif args.command == 'check-env':
        run_check_env()


def run_correlate(args):
    """执行关联分析和可视化"""
    print("AWS Security Configuration Correlator")
    print("=" * 60)

    # 处理 --use-latest 参数
    if args.use_latest:
        # 自动使用 latest 文件
        args.waf_json = 'waf_config_latest.json'
        args.alb_json = 'alb_config_latest.json'
        args.route53_json = 'route53_config_latest.json'
        print("\n使用 latest 文件模式")
    else:
        # 验证必须手动指定三个文件
        if not args.waf_json or not args.alb_json or not args.route53_json:
            print("\n✗ 错误: 必须指定三个 JSON 文件，或使用 --use-latest 参数", file=sys.stderr)
            print("\n使用示例:", file=sys.stderr)
            print("  方式 1 (手动指定): python security_audit_cli.py correlate waf.json alb.json route53.json", file=sys.stderr)
            print("  方式 2 (使用 latest): python security_audit_cli.py correlate --use-latest", file=sys.stderr)
            sys.exit(1)

    # 生成输出文件名
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"security_audit_report_{timestamp}.html"

    try:
        # 验证输入文件存在
        for file_path in [args.waf_json, args.alb_json, args.route53_json]:
            if not Path(file_path).exists():
                print(f"\n✗ Error: File not found: {file_path}", file=sys.stderr)
                print("  Please run the corresponding scan tool first", file=sys.stderr)
                sys.exit(1)

        # 加载数据和关联分析
        print(f"\nLoading data from:")
        print(f"  WAF:     {args.waf_json}")
        print(f"  ALB:     {args.alb_json}")
        print(f"  Route53: {args.route53_json}")

        correlator = SecurityConfigCorrelator(
            args.waf_json,
            args.alb_json,
            args.route53_json,
            debug=args.debug
        )

        print("\n" + "=" * 60)
        print("Correlating resources...")
        correlator.correlate_waf_alb()
        correlator.correlate_route53_alb()

        print("\nDetecting security issues...")
        unprotected = correlator.detect_unprotected_albs()
        orphans = correlator.detect_orphan_dns_records()
        unused = correlator.detect_unused_waf_acls()

        print(f"  ├─ Unprotected Public ALBs: {len(unprotected)}")
        print(f"  ├─ Orphan DNS Records:      {len(orphans)}")
        print(f"  └─ Unused WAF ACLs:         {len(unused)}")

        # 生成统计
        stats = correlator.generate_statistics()
        print(f"\nStatistics:")
        print(f"  ├─ Total ALBs:          {stats['total_albs']}")
        print(f"  ├─ Total WAF ACLs:      {stats['total_wafs']}")
        print(f"  ├─ WAF Coverage:        {stats['waf_coverage_rate']}%")
        print(f"  └─ DNS Correlations:    {stats['total_dns_records']}")

        # 显示警告
        if correlator.warnings:
            print(f"\n⚠️  Warnings: {len(correlator.warnings)}")
            for warning in correlator.warnings[:5]:
                print(f"  - {warning['message']}")
            if len(correlator.warnings) > 5:
                print(f"  ... and {len(correlator.warnings) - 5} more (see report)")

        # 生成可视化
        print("\n" + "=" * 60)
        print("Generating visualizations...")
        visualizer = SecurityVisualizer(correlator, debug=args.debug)

        visualizer.render_html(args.output)
        print(f"\n✓ HTML report generated: {args.output}")

        # 可选：输出 JSON
        if args.json:
            json_output = args.output.replace('.html', '.json')
            visualizer.save_json_data(json_output)
            print(f"✓ JSON data saved:       {json_output}")

        print("\n" + "=" * 60)
        print("Analysis complete!")
        print(f"\nOpen the report in your browser:")
        print(f"  open {args.output}  # macOS")
        print(f"  start {args.output} # Windows")
        print(f"  xdg-open {args.output} # Linux")

    except KeyboardInterrupt:
        print("\n\n✗ Operation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}", file=sys.stderr)
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def run_check_env():
    """检查环境依赖"""
    print("Checking environment prerequisites...")
    print("=" * 60)

    issues = []

    # 检查 Python 版本
    import sys
    py_version = sys.version_info
    print(f"\n✓ Python version: {py_version.major}.{py_version.minor}.{py_version.micro}")
    if py_version.major < 3 or (py_version.major == 3 and py_version.minor < 7):
        issues.append("Python 3.7+ is required")

    # 检查 networkx
    try:
        import networkx
        print(f"✓ networkx: {networkx.__version__}")
    except ImportError:
        print("✗ networkx: Not installed")
        issues.append("networkx is required (pip install networkx)")

    # 检查 jinja2
    try:
        import jinja2
        print(f"✓ jinja2: {jinja2.__version__}")
    except ImportError:
        print("✗ jinja2: Not installed")
        issues.append("jinja2 is required (pip install jinja2)")

    # 检查 boto3
    try:
        import boto3
        print(f"✓ boto3: {boto3.__version__}")
    except ImportError:
        print("✗ boto3: Not installed")
        issues.append("boto3 is required (pip install boto3)")

    # 检查模板文件
    template_dir = Path(__file__).parent / 'templates'
    required_templates = [
        'report_template.html',
        'network_graph.js',
        'tree_diagram.js',
        'dashboard_charts.js',
        'styles.css'
    ]

    print(f"\nTemplate files:")
    for template in required_templates:
        template_path = template_dir / template
        if template_path.exists():
            print(f"✓ {template}")
        else:
            print(f"✗ {template}")
            issues.append(f"Missing template: {template}")

    # 总结
    print("\n" + "=" * 60)
    if issues:
        print("\n✗ Issues found:")
        for issue in issues:
            print(f"  - {issue}")
        print("\nPlease install missing dependencies:")
        print("  pip install -r requirements.txt")
        sys.exit(1)
    else:
        print("\n✓ All prerequisites are satisfied!")
        print("  You can now use the security_audit_cli.py tool")


if __name__ == '__main__':
    main()
