#!/usr/bin/env python3
"""
WAF 配置分析工具

分析从 get_waf_config.py 导出的 JSON 数据
生成可读的报告和统计信息
"""

import json
import argparse
from collections import defaultdict
from typing import Dict, List, Any


class WAFConfigAnalyzer:
    """WAF 配置分析器"""

    def __init__(self, json_file: str):
        """加载 JSON 数据"""
        with open(json_file, 'r', encoding='utf-8') as f:
            self.data = json.load(f)

    def analyze_rules(self):
        """分析所有规则"""
        print("\n" + "="*80)
        print("规则分析")
        print("="*80)

        rule_types = defaultdict(int)
        rule_actions = defaultdict(int)

        for account in self.data:
            account_id = account.get('account_info', {}).get('account_id', 'Unknown')

            for region_data in account.get('regions', []):
                # 分析 CloudFront ACLs
                for acl in region_data.get('cloudfront_acls', []):
                    self._analyze_acl_rules(acl, rule_types, rule_actions)

                # 分析 Regional ACLs
                for acl in region_data.get('regional_acls', []):
                    self._analyze_acl_rules(acl, rule_types, rule_actions)

        print("\n规则类型分布:")
        for rule_type, count in sorted(rule_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  {rule_type}: {count}")

        print("\n规则动作分布:")
        for action, count in sorted(rule_actions.items(), key=lambda x: x[1], reverse=True):
            print(f"  {action}: {count}")

    def analyze_resources(self):
        """分析关联资源"""
        print("\n" + "="*80)
        print("关联资源分析")
        print("="*80)

        resource_types = defaultdict(int)
        total_resources = 0
        acls_with_resources = 0
        acls_without_resources = 0

        for account in self.data:
            account_id = account.get('account_info', {}).get('account_id', 'Unknown')

            for region_data in account.get('regions', []):
                # 分析所有 ACL 的关联资源
                all_acls = region_data.get('cloudfront_acls', []) + region_data.get('regional_acls', [])

                for acl in all_acls:
                    resources = acl.get('associated_resources', [])
                    if resources:
                        acls_with_resources += 1
                        total_resources += len(resources)

                        # 统计资源类型
                        for resource in resources:
                            friendly_type = resource.get('friendly_type', 'Unknown')
                            resource_types[friendly_type] += 1
                    else:
                        acls_without_resources += 1

        total_acls = acls_with_resources + acls_without_resources

        print(f"\n资源统计:")
        print(f"  Web ACL 总数: {total_acls}")
        print(f"  有关联资源的 ACL: {acls_with_resources}")
        print(f"  无关联资源的 ACL: {acls_without_resources}")
        print(f"  关联资源总数: {total_resources}")

        if resource_types:
            print(f"\n资源类型分布:")
            for resource_type, count in sorted(resource_types.items(), key=lambda x: x[1], reverse=True):
                print(f"  {resource_type}: {count}")

    def _analyze_acl_rules(self, acl: Dict, rule_types: Dict, rule_actions: Dict):
        """分析单个 ACL 的规则"""
        detail = acl.get('detail', {})
        rules = detail.get('Rules', [])

        for rule in rules:
            # 规则类型
            statement = rule.get('Statement', {})
            rule_type = self._get_rule_type(statement)
            rule_types[rule_type] += 1

            # 规则动作
            action = rule.get('Action', {})
            if 'Allow' in action:
                rule_actions['Allow'] += 1
            elif 'Block' in action:
                rule_actions['Block'] += 1
            elif 'Count' in action:
                rule_actions['Count'] += 1
            elif 'Captcha' in action:
                rule_actions['Captcha'] += 1

    def _get_rule_type(self, statement: Dict) -> str:
        """识别规则类型"""
        if 'ManagedRuleGroupStatement' in statement:
            vendor = statement['ManagedRuleGroupStatement'].get('VendorName', 'Unknown')
            name = statement['ManagedRuleGroupStatement'].get('Name', 'Unknown')
            return f"Managed: {vendor}/{name}"
        elif 'RateBasedStatement' in statement:
            return "Rate-based"
        elif 'IPSetReferenceStatement' in statement:
            return "IP Set"
        elif 'GeoMatchStatement' in statement:
            return "Geo Match"
        elif 'ByteMatchStatement' in statement:
            return "Byte Match"
        elif 'SizeConstraintStatement' in statement:
            return "Size Constraint"
        elif 'SqliMatchStatement' in statement:
            return "SQLi Match"
        elif 'XssMatchStatement' in statement:
            return "XSS Match"
        elif 'AndStatement' in statement:
            return "AND Logic"
        elif 'OrStatement' in statement:
            return "OR Logic"
        elif 'NotStatement' in statement:
            return "NOT Logic"
        else:
            return "Other"

    def list_all_acls(self):
        """列出所有 Web ACL"""
        print("\n" + "="*80)
        print("Web ACL 清单")
        print("="*80)

        for account in self.data:
            account_id = account.get('account_info', {}).get('account_id', 'Unknown')
            print(f"\n账户: {account_id}")

            for region_data in account.get('regions', []):
                region = region_data['region']

                # CloudFront ACLs
                for acl in region_data.get('cloudfront_acls', []):
                    self._print_acl_info(acl, region, 'CLOUDFRONT')

                # Regional ACLs
                for acl in region_data.get('regional_acls', []):
                    self._print_acl_info(acl, region, 'REGIONAL')

    def _print_acl_info(self, acl: Dict, region: str, scope: str):
        """打印单个 ACL 信息"""
        summary = acl.get('summary', {})
        detail = acl.get('detail', {})

        name = summary.get('Name', 'Unknown')
        acl_id = summary.get('Id', 'Unknown')
        capacity = detail.get('Capacity', 0)
        rule_count = len(detail.get('Rules', []))

        print(f"\n  [{scope}] {name}")
        print(f"    区域: {region}")
        print(f"    ID: {acl_id}")
        print(f"    容量: {capacity} WCU")
        print(f"    规则数: {rule_count}")

        # 关联资源 - 使用新的数据结构
        resources = acl.get('associated_resources', [])
        if resources:
            print(f"    关联资源: {len(resources)} 个")
            for resource in resources[:5]:  # 只显示前5个
                friendly_type = resource.get('friendly_type', 'Unknown')
                resource_id = resource.get('resource_id', resource.get('arn', 'Unknown'))
                # 如果资源 ID 太长，截断显示
                if len(resource_id) > 60:
                    resource_id = resource_id[:57] + '...'
                print(f"      - [{friendly_type}] {resource_id}")
            if len(resources) > 5:
                print(f"      ... 还有 {len(resources) - 5} 个资源")
        else:
            print(f"    关联资源: 无")

    def find_by_name(self, name_pattern: str):
        """根据名称查找 Web ACL"""
        print(f"\n搜索包含 '{name_pattern}' 的 Web ACL:")
        print("="*80)

        found = False
        for account in self.data:
            account_id = account.get('account_info', {}).get('account_id', 'Unknown')

            for region_data in account.get('regions', []):
                region = region_data['region']

                for acl in region_data.get('cloudfront_acls', []) + region_data.get('regional_acls', []):
                    acl_name = acl.get('summary', {}).get('Name', '')
                    if name_pattern.lower() in acl_name.lower():
                        found = True
                        print(f"\n✓ 找到: {acl_name}")
                        print(f"  账户: {account_id}")
                        print(f"  区域: {region}")
                        self._print_detailed_rules(acl)

        if not found:
            print("  未找到匹配的 Web ACL")

    def _print_detailed_rules(self, acl: Dict):
        """打印详细规则信息"""
        detail = acl.get('detail', {})
        rules = detail.get('Rules', [])

        if not rules:
            print("  无规则")
            return

        print(f"  规则列表:")
        for i, rule in enumerate(rules, 1):
            rule_name = rule.get('Name', 'Unnamed')
            priority = rule.get('Priority', -1)
            action = self._get_action_name(rule.get('Action', {}))

            print(f"    {i}. [{priority}] {rule_name} -> {action}")

    def _get_action_name(self, action: Dict) -> str:
        """获取动作名称"""
        if 'Allow' in action:
            return "Allow"
        elif 'Block' in action:
            return "Block"
        elif 'Count' in action:
            return "Count"
        elif 'Captcha' in action:
            return "Captcha"
        else:
            return "Unknown"

    def export_csv(self, output_file: str):
        """导出为 CSV 格式"""
        import csv

        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Account ID', 'Region', 'Scope', 'ACL Name', 'ACL ID',
                'Capacity', 'Rule Count', 'Associated Resources'
            ])

            for account in self.data:
                account_id = account.get('account_info', {}).get('account_id', 'Unknown')

                for region_data in account.get('regions', []):
                    region = region_data['region']

                    for acl in region_data.get('cloudfront_acls', []):
                        self._write_acl_row(writer, account_id, region, 'CLOUDFRONT', acl)

                    for acl in region_data.get('regional_acls', []):
                        self._write_acl_row(writer, account_id, region, 'REGIONAL', acl)

        print(f"\n✓ CSV 已导出到: {output_file}")

    def _write_acl_row(self, writer, account_id: str, region: str, scope: str, acl: Dict):
        """写入 CSV 行"""
        summary = acl.get('summary', {})
        detail = acl.get('detail', {})

        # 使用新的关联资源数据结构
        associated_resources = acl.get('associated_resources', [])

        writer.writerow([
            account_id,
            region,
            scope,
            summary.get('Name', ''),
            summary.get('Id', ''),
            detail.get('Capacity', 0),
            len(detail.get('Rules', [])),
            len(associated_resources)
        ])


def main():
    parser = argparse.ArgumentParser(description='分析 WAF 配置数据')

    parser.add_argument(
        'json_file',
        help='WAF 配置 JSON 文件'
    )

    parser.add_argument(
        '-l', '--list',
        action='store_true',
        help='列出所有 Web ACL'
    )

    parser.add_argument(
        '-a', '--analyze',
        action='store_true',
        help='分析规则统计'
    )

    parser.add_argument(
        '-r', '--resources',
        action='store_true',
        help='分析关联资源统计'
    )

    parser.add_argument(
        '-s', '--search',
        help='搜索指定名称的 Web ACL'
    )

    parser.add_argument(
        '-c', '--csv',
        help='导出为 CSV 文件'
    )

    args = parser.parse_args()

    # 创建分析器
    analyzer = WAFConfigAnalyzer(args.json_file)

    # 执行操作
    if args.list:
        analyzer.list_all_acls()

    if args.analyze:
        analyzer.analyze_rules()

    if args.resources:
        analyzer.analyze_resources()

    if args.search:
        analyzer.find_by_name(args.search)

    if args.csv:
        analyzer.export_csv(args.csv)

    # 如果没有指定任何操作，显示所有
    if not any([args.list, args.analyze, args.resources, args.search, args.csv]):
        analyzer.list_all_acls()
        analyzer.analyze_rules()
        analyzer.analyze_resources()


if __name__ == '__main__':
    main()
