#!/usr/bin/env python3
"""
Route53 配置分析工具

分析从 get_route53_config.py 导出的 JSON 数据
生成可读的报告和统计信息
"""

import json
import argparse
import csv
from collections import defaultdict
from typing import Dict, List, Any


class Route53ConfigAnalyzer:
    """Route53 配置分析器"""

    def __init__(self, json_file: str):
        """加载 JSON 数据"""
        with open(json_file, 'r', encoding='utf-8') as f:
            self.data = json.load(f)

    def list_all_zones(self):
        """列出所有 Hosted Zones"""
        print("\n" + "="*80)
        print("所有 Hosted Zones")
        print("="*80)

        for account in self.data:
            account_id = account.get('account_info', {}).get('account_id', 'Unknown')
            profile = account.get('profile', 'Unknown')

            print(f"\n账户: {account_id} ({profile})")

            for zone in account.get('hosted_zones', []):
                basic = zone['basic_info']
                zone_name = basic['Name']
                zone_type = "私有" if basic['Config']['PrivateZone'] else "公有"
                record_count = basic['ResourceRecordSetCount']

                print(f"  • {zone_name} ({zone_type}, {record_count} 条记录)")

                if basic['Config'].get('Comment'):
                    print(f"    注释: {basic['Config']['Comment']}")

                # 如果是私有 Zone，显示 VPC 关联
                vpcs = zone.get('vpcs', [])
                if vpcs:
                    print(f"    关联 VPC: {len(vpcs)} 个")
                    for vpc in vpcs[:3]:  # 最多显示前 3 个
                        vpc_id = vpc.get('VPCId', 'Unknown')
                        vpc_name = vpc.get('VPCName', 'N/A')
                        vpc_region = vpc.get('VPCRegion', 'Unknown')
                        print(f"      - {vpc_id} ({vpc_name}) @ {vpc_region}")
                    if len(vpcs) > 3:
                        print(f"      ... 还有 {len(vpcs) - 3} 个")

    def analyze_by_record_type(self):
        """按 DNS 记录类型统计"""
        print("\n" + "="*80)
        print("DNS 记录类型统计")
        print("="*80)

        global_type_stats = defaultdict(int)

        for account in self.data:
            for zone in account.get('hosted_zones', []):
                for record_type, count in zone.get('record_type_summary', {}).items():
                    global_type_stats[record_type] += count

        print("\n全局记录类型分布:")
        for record_type, count in sorted(global_type_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {record_type:10s}: {count:5d}")

        total_records = sum(global_type_stats.values())
        print(f"\n总记录数: {total_records}")

    def analyze_by_zone_type(self):
        """按公有/私有 Zone 统计"""
        print("\n" + "="*80)
        print("Hosted Zone 类型统计")
        print("="*80)

        public_count = 0
        private_count = 0
        public_records = 0
        private_records = 0

        for account in self.data:
            for zone in account.get('hosted_zones', []):
                is_private = zone['basic_info']['Config']['PrivateZone']
                record_count = zone['basic_info']['ResourceRecordSetCount']

                if is_private:
                    private_count += 1
                    private_records += record_count
                else:
                    public_count += 1
                    public_records += record_count

        total_zones = public_count + private_count
        total_records = public_records + private_records

        print(f"\n总计:")
        print(f"  公有 Zone: {public_count} ({public_count/total_zones*100:.1f}%), {public_records} 条记录")
        print(f"  私有 Zone: {private_count} ({private_count/total_zones*100:.1f}%), {private_records} 条记录")
        print(f"  总 Zone: {total_zones}")
        print(f"  总记录: {total_records}")

    def analyze_routing_policies(self):
        """分析路由策略使用情况"""
        print("\n" + "="*80)
        print("路由策略统计")
        print("="*80)

        policy_stats = defaultdict(int)

        for account in self.data:
            for zone in account.get('hosted_zones', []):
                for record in zone.get('records', []):
                    policy_type = record.get('RoutingPolicy', {}).get('Type', 'Simple')
                    policy_stats[policy_type] += 1

        print("\n路由策略分布:")
        for policy, count in sorted(policy_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {policy:15s}: {count:5d}")

        total_records = sum(policy_stats.values())
        print(f"\n总记录数: {total_records}")

    def find_missing_health_checks(self):
        """查找缺少健康检查的故障转移/加权记录（安全审计）"""
        print("\n" + "="*80)
        print("缺少健康检查的高级路由策略记录（安全审计）")
        print("="*80)

        found_any = False

        for account in self.data:
            account_id = account.get('account_info', {}).get('account_id', 'Unknown')
            profile = account.get('profile', 'Unknown')

            account_has_issues = False

            for zone in account.get('hosted_zones', []):
                zone_name = zone['basic_info']['Name']

                for record in zone.get('records', []):
                    routing = record.get('RoutingPolicy', {})

                    # 故障转移、加权、延迟路由策略应该配置健康检查
                    if routing.get('Type') in ['Failover', 'Weighted', 'Latency', 'Multivalue']:
                        if not record.get('HealthCheckId'):
                            if not account_has_issues:
                                print(f"\n账户: {account_id} ({profile})")
                                account_has_issues = True
                                found_any = True

                            print(f"  ⚠️  Zone: {zone_name}")
                            print(f"      记录: {record['Name']} ({record['Type']})")
                            print(f"      路由策略: {routing['Type']}")
                            print(f"      ✗ 缺少健康检查配置")

        if not found_any:
            print("\n✓ 所有高级路由策略记录都已配置健康检查（或未使用高级路由策略）")

    def search_by_name(self, pattern: str):
        """按 Zone 名称或记录名称搜索"""
        print("\n" + "="*80)
        print(f"搜索结果: '{pattern}'")
        print("="*80)

        found_any = False

        for account in self.data:
            account_id = account.get('account_info', {}).get('account_id', 'Unknown')
            profile = account.get('profile', 'Unknown')

            for zone in account.get('hosted_zones', []):
                zone_name = zone['basic_info']['Name']

                # 搜索 Zone 名称
                if pattern.lower() in zone_name.lower():
                    found_any = True
                    print(f"\n✓ Zone: {zone_name}")
                    print(f"  账户: {account_id} ({profile})")
                    print(f"  记录数: {zone['basic_info']['ResourceRecordSetCount']}")
                    print(f"  类型: {'私有' if zone['basic_info']['Config']['PrivateZone'] else '公有'}")

                # 搜索记录名称
                for record in zone.get('records', []):
                    if pattern.lower() in record['Name'].lower():
                        found_any = True
                        print(f"\n✓ 记录: {record['Name']} ({record['Type']})")
                        print(f"  所属 Zone: {zone_name}")
                        print(f"  账户: {account_id} ({profile})")

                        if record.get('AliasTarget'):
                            alias = record['AliasTarget']
                            print(f"  Alias 目标: {alias['DNSName']}")
                            print(f"  目标类型: {alias.get('TargetType', 'Unknown')}")
                        elif record.get('ResourceRecords'):
                            values = [rr['Value'] for rr in record['ResourceRecords']]
                            print(f"  值: {', '.join(values[:3])}")
                            if len(values) > 3:
                                print(f"       ... 还有 {len(values) - 3} 个值")

                        routing = record.get('RoutingPolicy', {})
                        if routing.get('Type') != 'Simple':
                            print(f"  路由策略: {routing['Type']}")

        if not found_any:
            print(f"\n未找到匹配 '{pattern}' 的 Zone 或记录")

    def search_by_record_value(self, pattern: str):
        """按记录值搜索（IP 地址、CNAME 目标等）"""
        print("\n" + "="*80)
        print(f"按记录值搜索: '{pattern}'")
        print("="*80)

        found_any = False

        for account in self.data:
            account_id = account.get('account_info', {}).get('account_id', 'Unknown')
            profile = account.get('profile', 'Unknown')

            for zone in account.get('hosted_zones', []):
                zone_name = zone['basic_info']['Name']

                for record in zone.get('records', []):
                    # 搜索 ResourceRecords 的值
                    if record.get('ResourceRecords'):
                        for rr in record['ResourceRecords']:
                            if pattern.lower() in rr['Value'].lower():
                                found_any = True
                                print(f"\n✓ {record['Name']} ({record['Type']})")
                                print(f"  Zone: {zone_name}")
                                print(f"  账户: {account_id} ({profile})")
                                print(f"  匹配值: {rr['Value']}")

                    # 搜索 Alias 目标
                    if record.get('AliasTarget'):
                        dns_name = record['AliasTarget']['DNSName']
                        if pattern.lower() in dns_name.lower():
                            found_any = True
                            print(f"\n✓ {record['Name']} ({record['Type']}) [Alias]")
                            print(f"  Zone: {zone_name}")
                            print(f"  账户: {account_id} ({profile})")
                            print(f"  Alias 目标: {dns_name}")
                            print(f"  目标类型: {record['AliasTarget'].get('TargetType', 'Unknown')}")

        if not found_any:
            print(f"\n未找到匹配 '{pattern}' 的记录值")

    def export_csv(self, output_file: str):
        """导出为 CSV"""
        print(f"\n导出到 CSV: {output_file}")

        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Account_ID', 'Profile', 'Zone_Name', 'Zone_Type',
                'Record_Name', 'Record_Type', 'TTL',
                'Value', 'Alias_Target', 'Alias_Target_Type',
                'Routing_Policy', 'Routing_Details',
                'Health_Check_ID', 'Set_Identifier'
            ]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for account in self.data:
                account_id = account.get('account_info', {}).get('account_id', 'Unknown')
                profile = account.get('profile', 'Unknown')

                for zone in account.get('hosted_zones', []):
                    zone_name = zone['basic_info']['Name']
                    zone_type = "Private" if zone['basic_info']['Config']['PrivateZone'] else "Public"

                    for record in zone.get('records', []):
                        routing = record.get('RoutingPolicy', {})
                        routing_policy = routing.get('Type', 'Simple')
                        routing_details = json.dumps(routing.get('Details', {})) if routing.get('Details') else ''

                        # 处理多值记录（一条记录有多个 ResourceRecords）
                        if record.get('ResourceRecords'):
                            for rr in record['ResourceRecords']:
                                row = {
                                    'Account_ID': account_id,
                                    'Profile': profile,
                                    'Zone_Name': zone_name,
                                    'Zone_Type': zone_type,
                                    'Record_Name': record['Name'],
                                    'Record_Type': record['Type'],
                                    'TTL': record.get('TTL', ''),
                                    'Value': rr['Value'],
                                    'Alias_Target': '',
                                    'Alias_Target_Type': '',
                                    'Routing_Policy': routing_policy,
                                    'Routing_Details': routing_details,
                                    'Health_Check_ID': record.get('HealthCheckId', ''),
                                    'Set_Identifier': record.get('SetIdentifier', '')
                                }
                                writer.writerow(row)

                        # Alias 记录
                        elif record.get('AliasTarget'):
                            alias = record['AliasTarget']
                            row = {
                                'Account_ID': account_id,
                                'Profile': profile,
                                'Zone_Name': zone_name,
                                'Zone_Type': zone_type,
                                'Record_Name': record['Name'],
                                'Record_Type': record['Type'],
                                'TTL': '',
                                'Value': '',
                                'Alias_Target': alias['DNSName'],
                                'Alias_Target_Type': alias.get('TargetType', 'Unknown'),
                                'Routing_Policy': routing_policy,
                                'Routing_Details': routing_details,
                                'Health_Check_ID': record.get('HealthCheckId', ''),
                                'Set_Identifier': record.get('SetIdentifier', '')
                            }
                            writer.writerow(row)

        print(f"✓ 已导出 CSV 文件")


def main():
    parser = argparse.ArgumentParser(
        description='分析 Route53 配置 JSON 文件'
    )

    parser.add_argument('json_file',
                       help='Route53 配置 JSON 文件路径')

    parser.add_argument('--list', action='store_true',
                       help='列出所有 Hosted Zones')

    parser.add_argument('--by-record-type', action='store_true',
                       help='按 DNS 记录类型统计')

    parser.add_argument('--by-zone-type', action='store_true',
                       help='按 Zone 类型统计（公有/私有）')

    parser.add_argument('--routing-policies', action='store_true',
                       help='分析路由策略使用情况')

    parser.add_argument('--missing-health-checks', action='store_true',
                       help='查找缺少健康检查的故障转移/加权记录（安全审计）')

    parser.add_argument('--search',
                       help='按 Zone 名称或记录名称搜索')

    parser.add_argument('--search-value',
                       help='按记录值搜索（IP 地址、CNAME 目标等）')

    parser.add_argument('--csv',
                       help='导出为 CSV 文件')

    args = parser.parse_args()

    try:
        analyzer = Route53ConfigAnalyzer(args.json_file)
    except FileNotFoundError:
        print(f"✗ 文件不存在: {args.json_file}")
        return 1
    except json.JSONDecodeError as e:
        print(f"✗ JSON 解析失败: {str(e)}")
        return 1
    except Exception as e:
        print(f"✗ 加载文件失败: {str(e)}")
        return 1

    # 如果没有指定任何选项，执行完整分析
    if not any([args.list, args.by_record_type, args.by_zone_type,
                args.routing_policies, args.missing_health_checks,
                args.search, args.search_value, args.csv]):
        analyzer.list_all_zones()
        analyzer.analyze_by_record_type()
        analyzer.analyze_by_zone_type()
        analyzer.analyze_routing_policies()
        analyzer.find_missing_health_checks()
    else:
        # 执行指定的分析
        if args.list:
            analyzer.list_all_zones()

        if args.by_record_type:
            analyzer.analyze_by_record_type()

        if args.by_zone_type:
            analyzer.analyze_by_zone_type()

        if args.routing_policies:
            analyzer.analyze_routing_policies()

        if args.missing_health_checks:
            analyzer.find_missing_health_checks()

        if args.search:
            analyzer.search_by_name(args.search)

        if args.search_value:
            analyzer.search_by_record_value(args.search_value)

        if args.csv:
            analyzer.export_csv(args.csv)

    return 0


if __name__ == '__main__':
    exit(main())
