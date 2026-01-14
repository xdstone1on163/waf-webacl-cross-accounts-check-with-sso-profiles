#!/usr/bin/env python3
"""
ALB 配置分析工具

分析从 get_alb_config.py 导出的 JSON 数据
生成可读的报告和统计信息
"""

import json
import argparse
import csv
from collections import defaultdict
from typing import Dict, List, Any


class ALBConfigAnalyzer:
    """ALB 配置分析器"""

    def __init__(self, json_file: str):
        """加载 JSON 数据"""
        with open(json_file, 'r', encoding='utf-8') as f:
            self.data = json.load(f)

    def list_all_albs(self):
        """列出所有 ALB"""
        print("\n" + "="*80)
        print("所有 ALB 列表")
        print("="*80)

        for account in self.data:
            account_id = account.get('account_info', {}).get('account_id', 'Unknown')
            profile = account.get('profile', 'Unknown')

            print(f"\n账户: {account_id} ({profile})")

            for region_data in account.get('regions', []):
                region = region_data['region']
                albs = region_data.get('load_balancers', [])

                if albs:
                    print(f"\n  区域: {region}")

                    for alb in albs:
                        basic = alb.get('basic_info', {})
                        waf = alb.get('waf_association', {})

                        name = basic.get('LoadBalancerName', 'Unknown')
                        alb_type = basic.get('FriendlyType', basic.get('Type', 'Unknown'))
                        state = basic.get('State', {}).get('Code', 'Unknown')
                        dns = basic.get('DNSName', 'N/A')
                        waf_status = "✓ 有 WAF" if waf.get('has_waf') else "✗ 无 WAF"

                        if waf.get('has_waf'):
                            waf_name = waf.get('WebACL', {}).get('Name', 'Unknown')
                            waf_status += f" ({waf_name})"

                        print(f"    • {name}")
                        print(f"      类型: {alb_type}")
                        print(f"      状态: {state}")
                        print(f"      DNS: {dns}")
                        print(f"      WAF: {waf_status}")

    def analyze_waf_coverage(self):
        """分析 WAF 覆盖率"""
        print("\n" + "="*80)
        print("WAF 覆盖率分析")
        print("="*80)

        # 全局统计
        total_albs = 0
        total_with_waf = 0
        total_without_waf = 0

        # 按账户统计
        account_stats = []

        for account in self.data:
            account_id = account.get('account_info', {}).get('account_id', 'Unknown')
            profile = account.get('profile', 'Unknown')

            account_albs = 0
            account_with_waf = 0

            for region_data in account.get('regions', []):
                albs = region_data.get('load_balancers', [])
                account_albs += len(albs)
                account_with_waf += sum(1 for alb in albs if alb['waf_association']['has_waf'])

            account_without_waf = account_albs - account_with_waf
            account_coverage = (account_with_waf / account_albs * 100) if account_albs > 0 else 0

            account_stats.append({
                'account_id': account_id,
                'profile': profile,
                'total': account_albs,
                'with_waf': account_with_waf,
                'without_waf': account_without_waf,
                'coverage': account_coverage
            })

            total_albs += account_albs
            total_with_waf += account_with_waf
            total_without_waf += account_without_waf

        # 打印按账户统计
        print("\n按账户统计:")
        for stat in account_stats:
            print(f"\n  账户 {stat['account_id']} ({stat['profile']}):")
            print(f"    总 ALB 数: {stat['total']}")
            print(f"    有 WAF: {stat['with_waf']} ({stat['coverage']:.1f}%)")
            print(f"    无 WAF: {stat['without_waf']} ({100-stat['coverage']:.1f}%)")

        # 打印全局统计
        global_coverage = (total_with_waf / total_albs * 100) if total_albs > 0 else 0

        print(f"\n全局统计:")
        print(f"  总 ALB 数: {total_albs}")
        print(f"  有 WAF: {total_with_waf} ({global_coverage:.1f}%)")
        print(f"  无 WAF: {total_without_waf} ({100-global_coverage:.1f}%)")

    def find_without_waf(self):
        """列出未绑定 WAF 的 ALB"""
        print("\n" + "="*80)
        print("未绑定 WAF 的 ALB（安全审计）")
        print("="*80)

        found_any = False

        for account in self.data:
            account_id = account.get('account_info', {}).get('account_id', 'Unknown')
            profile = account.get('profile', 'Unknown')

            account_has_unwaf = False

            for region_data in account.get('regions', []):
                region = region_data['region']
                albs = region_data.get('load_balancers', [])

                unwaf_albs = [alb for alb in albs if not alb['waf_association']['has_waf']]

                if unwaf_albs:
                    if not account_has_unwaf:
                        print(f"\n账户: {account_id} ({profile})")
                        account_has_unwaf = True
                        found_any = True

                    print(f"\n  区域: {region}")

                    for alb in unwaf_albs:
                        basic = alb.get('basic_info', {})
                        name = basic.get('LoadBalancerName', 'Unknown')
                        alb_type = basic.get('FriendlyType', basic.get('Type', 'Unknown'))
                        scheme = basic.get('Scheme', 'Unknown')
                        dns = basic.get('DNSName', 'N/A')

                        print(f"    ⚠️  {name}")
                        print(f"        类型: {alb_type}")
                        print(f"        方案: {scheme}")
                        print(f"        DNS: {dns}")

        if not found_any:
            print("\n✓ 所有 ALB 都已绑定 WAF")

    def analyze_by_type(self):
        """按类型统计"""
        print("\n" + "="*80)
        print("按类型统计")
        print("="*80)

        type_stats = defaultdict(int)

        for account in self.data:
            for region_data in account.get('regions', []):
                for alb in region_data.get('load_balancers', []):
                    alb_type = alb.get('basic_info', {}).get('FriendlyType', 'Unknown')
                    type_stats[alb_type] += 1

        print("\n负载均衡器类型分布:")
        for alb_type, count in sorted(type_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {alb_type}: {count}")

    def analyze_by_region(self):
        """按区域统计"""
        print("\n" + "="*80)
        print("按区域统计")
        print("="*80)

        region_stats = defaultdict(lambda: {'total': 0, 'with_waf': 0})

        for account in self.data:
            for region_data in account.get('regions', []):
                region = region_data['region']
                albs = region_data.get('load_balancers', [])

                region_stats[region]['total'] += len(albs)
                region_stats[region]['with_waf'] += sum(
                    1 for alb in albs if alb['waf_association']['has_waf']
                )

        print("\n区域分布:")
        for region, stats in sorted(region_stats.items(), key=lambda x: x[1]['total'], reverse=True):
            total = stats['total']
            with_waf = stats['with_waf']
            coverage = (with_waf / total * 100) if total > 0 else 0

            print(f"  {region}: {total} 个 ALB ({with_waf} 个有 WAF, {coverage:.1f}%)")

    def search(self, name_pattern: str):
        """搜索指定名称的 ALB"""
        print("\n" + "="*80)
        print(f"搜索结果: '{name_pattern}'")
        print("="*80)

        found_any = False

        for account in self.data:
            account_id = account.get('account_info', {}).get('account_id', 'Unknown')
            profile = account.get('profile', 'Unknown')

            for region_data in account.get('regions', []):
                region = region_data['region']
                albs = region_data.get('load_balancers', [])

                matching_albs = [
                    alb for alb in albs
                    if name_pattern.lower() in alb.get('basic_info', {}).get('LoadBalancerName', '').lower()
                ]

                if matching_albs:
                    found_any = True
                    print(f"\n账户: {account_id} ({profile}), 区域: {region}")

                    for alb in matching_albs:
                        basic = alb.get('basic_info', {})
                        waf = alb.get('waf_association', {})

                        name = basic.get('LoadBalancerName', 'Unknown')
                        alb_type = basic.get('FriendlyType', basic.get('Type', 'Unknown'))
                        state = basic.get('State', {}).get('Code', 'Unknown')
                        dns = basic.get('DNSName', 'N/A')
                        waf_status = "有 WAF" if waf.get('has_waf') else "无 WAF"

                        if waf.get('has_waf'):
                            waf_name = waf.get('WebACL', {}).get('Name', 'Unknown')
                            waf_status += f" ({waf_name})"

                        print(f"  • {name}")
                        print(f"    类型: {alb_type}, 状态: {state}")
                        print(f"    DNS: {dns}")
                        print(f"    WAF: {waf_status}")

        if not found_any:
            print(f"\n未找到匹配 '{name_pattern}' 的 ALB")

    def export_csv(self, output_file: str):
        """导出为 CSV"""
        print(f"\n导出到 CSV: {output_file}")

        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Account_ID', 'Profile', 'Region', 'ALB_Name', 'Type',
                'State', 'Scheme', 'DNS_Name', 'VPC_ID',
                'Has_WAF', 'WAF_Name', 'WAF_ID', 'WAF_ARN',
                'Listener_Count', 'TargetGroup_Count'
            ]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for account in self.data:
                account_id = account.get('account_info', {}).get('account_id', 'Unknown')
                profile = account.get('profile', 'Unknown')

                for region_data in account.get('regions', []):
                    region = region_data['region']
                    albs = region_data.get('load_balancers', [])

                    for alb in albs:
                        basic = alb.get('basic_info', {})
                        waf = alb.get('waf_association', {})

                        row = {
                            'Account_ID': account_id,
                            'Profile': profile,
                            'Region': region,
                            'ALB_Name': basic.get('LoadBalancerName', ''),
                            'Type': basic.get('FriendlyType', basic.get('Type', '')),
                            'State': basic.get('State', {}).get('Code', ''),
                            'Scheme': basic.get('Scheme', ''),
                            'DNS_Name': basic.get('DNSName', ''),
                            'VPC_ID': basic.get('VpcId', ''),
                            'Has_WAF': 'Yes' if waf.get('has_waf') else 'No',
                            'WAF_Name': waf.get('WebACL', {}).get('Name', '') if waf.get('has_waf') else '',
                            'WAF_ID': waf.get('WebACL', {}).get('Id', '') if waf.get('has_waf') else '',
                            'WAF_ARN': waf.get('WebACL', {}).get('ARN', '') if waf.get('has_waf') else '',
                            'Listener_Count': len(alb.get('listeners', [])),
                            'TargetGroup_Count': len(alb.get('target_groups', []))
                        }

                        writer.writerow(row)

        print(f"✓ 已导出 CSV 文件")


def main():
    parser = argparse.ArgumentParser(
        description='ALB 配置分析工具',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('json_file', help='ALB 配置 JSON 文件')
    parser.add_argument('--list', action='store_true', help='列出所有 ALB')
    parser.add_argument('--waf-coverage', action='store_true', help='分析 WAF 覆盖率')
    parser.add_argument('--no-waf', action='store_true', help='列出未绑定 WAF 的 ALB')
    parser.add_argument('--by-type', action='store_true', help='按类型统计')
    parser.add_argument('--by-region', action='store_true', help='按区域统计')
    parser.add_argument('--search', help='搜索指定名称的 ALB')
    parser.add_argument('--csv', help='导出为 CSV 文件')

    args = parser.parse_args()

    # 加载分析器
    analyzer = ALBConfigAnalyzer(args.json_file)

    # 如果没有指定任何选项，执行全部分析
    if not any([args.list, args.waf_coverage, args.no_waf, args.by_type,
                args.by_region, args.search, args.csv]):
        analyzer.list_all_albs()
        analyzer.analyze_waf_coverage()
        analyzer.analyze_by_type()
        analyzer.analyze_by_region()
    else:
        # 执行指定的分析
        if args.list:
            analyzer.list_all_albs()

        if args.waf_coverage:
            analyzer.analyze_waf_coverage()

        if args.no_waf:
            analyzer.find_without_waf()

        if args.by_type:
            analyzer.analyze_by_type()

        if args.by_region:
            analyzer.analyze_by_region()

        if args.search:
            analyzer.search(args.search)

        if args.csv:
            analyzer.export_csv(args.csv)

    return 0


if __name__ == '__main__':
    exit(main())
