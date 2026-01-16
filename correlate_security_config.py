#!/usr/bin/env python3
"""
AWS Security Configuration Correlator

关联分析 WAF、ALB 和 Route53 的配置，识别安全漏洞。
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime
import networkx as nx


class SecurityConfigCorrelator:
    """安全配置关联分析器"""

    def __init__(self, waf_json_path: str, alb_json_path: str, route53_json_path: str, debug: bool = False):
        """
        初始化关联分析器

        Args:
            waf_json_path: WAF 配置 JSON 文件路径
            alb_json_path: ALB 配置 JSON 文件路径
            route53_json_path: Route53 配置 JSON 文件路径
            debug: 是否启用调试模式
        """
        self.waf_json_path = waf_json_path
        self.alb_json_path = alb_json_path
        self.route53_json_path = route53_json_path
        self.debug = debug

        # 原始数据
        self.waf_data = []
        self.alb_data = []
        self.route53_data = []

        # 索引
        self.alb_arn_index = {}  # ALB ARN -> ALB 详情
        self.alb_dns_index = {}  # ALB DNS Name -> ALB 详情
        self.waf_arn_index = {}  # WAF ARN -> WAF 详情

        # 关联结果
        self.waf_alb_correlations = []
        self.route53_alb_correlations = []

        # 安全问题
        self.unprotected_albs = []
        self.orphan_dns_records = []
        self.unused_waf_acls = []

        # 警告信息
        self.warnings = []

        # 元数据
        self.accounts = set()
        self.regions = set()

        # 加载数据
        self._load_data()

    def _load_data(self):
        """加载三个 JSON 文件"""
        try:
            # 加载 WAF 配置
            if self.debug:
                print(f"Loading WAF config from: {self.waf_json_path}")
            with open(self.waf_json_path, 'r') as f:
                self.waf_data = json.load(f)

            # 加载 ALB 配置
            if self.debug:
                print(f"Loading ALB config from: {self.alb_json_path}")
            with open(self.alb_json_path, 'r') as f:
                self.alb_data = json.load(f)

            # 加载 Route53 配置
            if self.debug:
                print(f"Loading Route53 config from: {self.route53_json_path}")
            with open(self.route53_json_path, 'r') as f:
                self.route53_data = json.load(f)

            # 构建索引
            self._build_indices()

        except FileNotFoundError as e:
            print(f"\n✗ Error: File not found: {e.filename}", file=sys.stderr)
            print(f"  Please run the corresponding scan tool first", file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"\n✗ Error: Invalid JSON", file=sys.stderr)
            print(f"  Line {e.lineno}, Column {e.colno}: {e.msg}", file=sys.stderr)
            sys.exit(1)

    def _build_indices(self):
        """构建索引以加速查找"""
        if self.debug:
            print("Building indices...")

        # 构建 ALB 索引
        for account_data in self.alb_data:
            account_id = account_data.get('account_info', {}).get('account_id', 'unknown')
            self.accounts.add(account_id)

            for region_data in account_data.get('regions', []):
                region = region_data.get('region', 'unknown')
                self.regions.add(region)

                for alb in region_data.get('load_balancers', []):
                    alb_info = alb.get('basic_info', {})
                    alb_arn = alb_info.get('LoadBalancerArn', '')
                    alb_dns = alb_info.get('DNSName', '')

                    # 添加账户和区域信息
                    alb['account_id'] = account_id
                    alb['region'] = region

                    if alb_arn:
                        self.alb_arn_index[alb_arn] = alb
                    if alb_dns:
                        self.alb_dns_index[alb_dns] = alb

        # 构建 WAF 索引
        for account_data in self.waf_data:
            account_id = account_data.get('account_info', {}).get('account_id', 'unknown')
            self.accounts.add(account_id)

            # Regional ACLs
            for region_data in account_data.get('regions', []):
                region = region_data.get('region', 'unknown')
                self.regions.add(region)

                for waf in region_data.get('regional_acls', []):
                    # WAF 数据格式: summary.ARN 而不是 webacl_arn
                    waf_arn = waf.get('summary', {}).get('ARN', '') or waf.get('detail', {}).get('ARN', '')

                    # 添加账户和区域信息
                    waf['account_id'] = account_id
                    waf['region'] = region
                    waf['scope'] = 'REGIONAL'

                    if waf_arn:
                        self.waf_arn_index[waf_arn] = waf

            # CloudFront ACLs
            for waf in account_data.get('cloudfront_acls', []):
                # WAF 数据格式: summary.ARN 而不是 webacl_arn
                waf_arn = waf.get('summary', {}).get('ARN', '') or waf.get('detail', {}).get('ARN', '')

                # 添加账户和区域信息
                waf['account_id'] = account_id
                waf['region'] = 'us-east-1'  # CloudFront is always in us-east-1
                waf['scope'] = 'CLOUDFRONT'

                if waf_arn:
                    self.waf_arn_index[waf_arn] = waf

        # 收集 Route53 账户信息
        for account_data in self.route53_data:
            account_id = account_data.get('account_info', {}).get('account_id', 'unknown')
            self.accounts.add(account_id)

        if self.debug:
            print(f"  Found {len(self.alb_arn_index)} ALBs")
            print(f"  Found {len(self.waf_arn_index)} WAF ACLs")
            print(f"  Accounts: {len(self.accounts)}")
            print(f"  Regions: {len(self.regions)}")

    @staticmethod
    def safe_get(obj, path, default=None):
        """安全获取嵌套字段，避免 KeyError"""
        try:
            for key in path.split('.'):
                obj = obj[key]
            return obj
        except (KeyError, TypeError, AttributeError):
            return default

    def correlate_waf_alb(self):
        """关联 WAF 和 ALB（双向验证）"""
        if self.debug:
            print("\nCorrelating WAF ↔ ALB...")

        # 正向匹配：WAF → ALB
        for waf_arn, waf in self.waf_arn_index.items():
            associated_resources = waf.get('associated_resources', [])

            for resource in associated_resources:
                resource_arn = resource.get('arn', '')
                resource_type = resource.get('resource_type_api', '')

                if resource_type == 'APPLICATION_LOAD_BALANCER':
                    alb = self.alb_arn_index.get(resource_arn)

                    if alb:
                        # 匹配成功
                        correlation = {
                            'waf': waf,
                            'alb': alb,
                            'match_type': 'waf_to_alb',
                            'consistent': False  # 待验证
                        }

                        # 验证反向关联
                        alb_waf_arn = self.safe_get(alb, 'waf_association.WebACL.ARN')
                        if alb_waf_arn == waf_arn:
                            correlation['consistent'] = True
                        else:
                            waf_name = waf.get('summary', {}).get('Name') or waf.get('detail', {}).get('Name', 'unknown')
                            self.warnings.append({
                                'type': 'WAF-ALB Inconsistency',
                                'message': f"WAF {waf_name} declares ALB {alb.get('basic_info', {}).get('LoadBalancerName')}, but ALB references different WAF",
                                'waf_arn': waf_arn,
                                'alb_arn': resource_arn
                            })

                        self.waf_alb_correlations.append(correlation)
                    else:
                        # WAF 声称有 ALB，但 ALB 不存在
                        waf_name = waf.get('summary', {}).get('Name') or waf.get('detail', {}).get('Name', 'unknown')
                        self.warnings.append({
                            'type': 'Missing ALB',
                            'message': f"WAF {waf_name} references missing ALB: {resource_arn}",
                            'waf_arn': waf_arn,
                            'alb_arn': resource_arn
                        })

        if self.debug:
            print(f"  Found {len(self.waf_alb_correlations)} WAF-ALB correlations")
            print(f"  Warnings: {len(self.warnings)}")

    def correlate_route53_alb(self):
        """关联 Route53 DNS 记录和 ALB（单向）"""
        if self.debug:
            print("\nCorrelating Route53 → ALB...")

        for account_data in self.route53_data:
            account_id = account_data.get('account_info', {}).get('account_id', 'unknown')

            for zone in account_data.get('hosted_zones', []):
                zone_name = zone.get('basic_info', {}).get('Name', 'unknown')

                for record in zone.get('records', []):
                    alias_target = record.get('AliasTarget')

                    if alias_target:
                        alias_dns = alias_target.get('DNSName', '')
                        target_type = alias_target.get('TargetType', '')

                        # 只处理 ELB 类型
                        if 'ELB' in target_type:
                            alb = self.alb_dns_index.get(alias_dns)

                            if alb:
                                # 匹配成功：DNS → ALB
                                correlation = {
                                    'dns_record': {
                                        'name': record.get('Name', ''),
                                        'type': record.get('Type', ''),
                                        'zone': zone_name,
                                        'account_id': account_id
                                    },
                                    'alb': alb,
                                    'waf': alb.get('waf_association'),
                                    'match_type': 'dns_to_alb'
                                }

                                self.route53_alb_correlations.append(correlation)
                            else:
                                # 孤儿 DNS 记录
                                self.orphan_dns_records.append({
                                    'severity': 'MEDIUM',
                                    'type': 'Orphan DNS Record',
                                    'resource': record.get('Name', ''),
                                    'target': alias_dns,
                                    'zone': zone_name,
                                    'account_id': account_id,
                                    'description': 'DNS record points to non-existent ALB'
                                })

        if self.debug:
            print(f"  Found {len(self.route53_alb_correlations)} DNS-ALB correlations")
            print(f"  Found {len(self.orphan_dns_records)} orphan DNS records")

    def detect_unprotected_albs(self):
        """查找未绑定 WAF 的公网 ALB"""
        if self.debug:
            print("\nDetecting unprotected ALBs...")

        for alb_arn, alb in self.alb_arn_index.items():
            scheme = self.safe_get(alb, 'basic_info.Scheme', '')
            has_waf = self.safe_get(alb, 'waf_association.has_waf', False)

            if scheme == 'internet-facing' and not has_waf:
                self.unprotected_albs.append({
                    'severity': 'HIGH',
                    'type': 'Unprotected Public ALB',
                    'resource': self.safe_get(alb, 'basic_info.LoadBalancerName', 'unknown'),
                    'arn': alb_arn,
                    'account_id': alb.get('account_id', 'unknown'),
                    'region': alb.get('region', 'unknown'),
                    'description': 'Internet-facing ALB without WAF protection'
                })

        if self.debug:
            print(f"  Found {len(self.unprotected_albs)} unprotected public ALBs")

        return self.unprotected_albs

    def detect_orphan_dns_records(self):
        """查找孤儿 DNS 记录（已在 correlate_route53_alb 中完成）"""
        return self.orphan_dns_records

    def detect_unused_waf_acls(self):
        """查找未使用的 WAF ACL"""
        if self.debug:
            print("\nDetecting unused WAF ACLs...")

        for waf_arn, waf in self.waf_arn_index.items():
            associated_resources = waf.get('associated_resources', [])

            if len(associated_resources) == 0:
                waf_name = waf.get('summary', {}).get('Name') or waf.get('detail', {}).get('Name', 'unknown')
                self.unused_waf_acls.append({
                    'severity': 'LOW',
                    'type': 'Unused WAF ACL',
                    'resource': waf_name,
                    'arn': waf_arn,
                    'account_id': waf.get('account_id', 'unknown'),
                    'region': waf.get('region', 'unknown'),
                    'description': 'WAF ACL with no associated resources (potential cost waste)'
                })

        if self.debug:
            print(f"  Found {len(self.unused_waf_acls)} unused WAF ACLs")

        return self.unused_waf_acls

    def build_graph(self) -> nx.DiGraph:
        """构建网络图数据结构"""
        if self.debug:
            print("\nBuilding network graph...")

        G = nx.DiGraph()

        # 添加 DNS 记录节点
        for correlation in self.route53_alb_correlations:
            dns_record = correlation['dns_record']
            dns_id = f"dns:{dns_record['name']}"

            G.add_node(dns_id,
                      type='dns',
                      label=dns_record['name'],
                      color='#4CAF50',  # 绿色
                      details=dns_record)

        # 添加 ALB 节点
        for alb_arn, alb in self.alb_arn_index.items():
            has_waf = self.safe_get(alb, 'waf_association.has_waf', False)
            scheme = self.safe_get(alb, 'basic_info.Scheme', '')
            alb_name = self.safe_get(alb, 'basic_info.LoadBalancerName', 'unknown')

            # 根据保护状态决定颜色
            if has_waf:
                color = '#2196F3'  # 蓝色（有 WAF）
            elif scheme == 'internet-facing':
                color = '#F44336'  # 红色（公网无 WAF）
            else:
                color = '#FFC107'  # 黄色（内网无 WAF）

            G.add_node(f"alb:{alb_arn}",
                      type='alb',
                      label=alb_name,
                      color=color,
                      details={
                          'name': alb_name,
                          'arn': alb_arn,
                          'dns_name': self.safe_get(alb, 'basic_info.DNSName'),
                          'scheme': scheme,
                          'has_waf': has_waf,
                          'account_id': alb.get('account_id'),
                          'region': alb.get('region')
                      })

        # 添加 WAF 节点
        for waf_arn, waf in self.waf_arn_index.items():
            waf_name = waf.get('summary', {}).get('Name') or waf.get('detail', {}).get('Name', 'unknown')

            G.add_node(f"waf:{waf_arn}",
                      type='waf',
                      label=waf_name,
                      color='#FF9800',  # 橙色
                      details={
                          'name': waf_name,
                          'arn': waf_arn,
                          'scope': waf.get('scope'),
                          'account_id': waf.get('account_id'),
                          'region': waf.get('region')
                      })

        # 添加 DNS → ALB 边
        for correlation in self.route53_alb_correlations:
            dns_record = correlation['dns_record']
            alb = correlation['alb']
            alb_arn = self.safe_get(alb, 'basic_info.LoadBalancerArn', '')

            if alb_arn:
                G.add_edge(f"dns:{dns_record['name']}",
                          f"alb:{alb_arn}",
                          label='resolves to')

        # 添加 ALB → WAF 边
        for alb_arn, alb in self.alb_arn_index.items():
            has_waf = self.safe_get(alb, 'waf_association.has_waf', False)
            if has_waf:
                waf_arn = self.safe_get(alb, 'waf_association.WebACL.ARN')
                if waf_arn:
                    G.add_edge(f"alb:{alb_arn}",
                              f"waf:{waf_arn}",
                              label='protected by')

        if self.debug:
            print(f"  Graph nodes: {G.number_of_nodes()}")
            print(f"  Graph edges: {G.number_of_edges()}")

        return G

    def generate_statistics(self) -> Dict:
        """生成统计数据"""
        if self.debug:
            print("\nGenerating statistics...")

        # ALB 统计
        total_albs = len(self.alb_arn_index)
        albs_with_waf = sum(1 for alb in self.alb_arn_index.values()
                           if self.safe_get(alb, 'waf_association.has_waf', False))
        albs_without_waf = total_albs - albs_with_waf
        waf_coverage_rate = round(albs_with_waf / total_albs * 100, 2) if total_albs > 0 else 0

        # 按账户统计
        by_account = []
        for account_id in self.accounts:
            account_albs = [alb for alb in self.alb_arn_index.values()
                           if alb.get('account_id') == account_id]
            account_wafs = [waf for waf in self.waf_arn_index.values()
                           if waf.get('account_id') == account_id]
            account_dns = sum(1 for corr in self.route53_alb_correlations
                             if corr['dns_record']['account_id'] == account_id)

            by_account.append({
                'account_id': account_id,
                'alb_count': len(account_albs),
                'waf_count': len(account_wafs),
                'dns_count': account_dns
            })

        # 按区域统计
        by_region = []
        for region in self.regions:
            region_albs = [alb for alb in self.alb_arn_index.values()
                          if alb.get('region') == region]
            region_wafs = [waf for waf in self.waf_arn_index.values()
                          if waf.get('region') == region]

            by_region.append({
                'region': region,
                'alb_count': len(region_albs),
                'waf_count': len(region_wafs)
            })

        # 按类型统计
        application_count = sum(1 for alb in self.alb_arn_index.values()
                               if self.safe_get(alb, 'basic_info.Type') == 'application')
        network_count = sum(1 for alb in self.alb_arn_index.values()
                           if self.safe_get(alb, 'basic_info.Type') == 'network')

        stats = {
            'total_albs': total_albs,
            'albs_with_waf': albs_with_waf,
            'albs_without_waf': albs_without_waf,
            'waf_coverage_rate': waf_coverage_rate,
            'total_wafs': len(self.waf_arn_index),
            'total_dns_records': len(self.route53_alb_correlations),
            'by_account': by_account,
            'by_region': by_region,
            'by_type': {
                'application': application_count,
                'network': network_count
            }
        }

        if self.debug:
            print(f"  WAF Coverage: {waf_coverage_rate}%")
            print(f"  Total ALBs: {total_albs}")
            print(f"  Total WAFs: {len(self.waf_arn_index)}")

        return stats


def main():
    """主程序（用于测试）"""
    import argparse

    parser = argparse.ArgumentParser(description='AWS Security Configuration Correlator')
    parser.add_argument('waf_json', help='WAF configuration JSON file')
    parser.add_argument('alb_json', help='ALB configuration JSON file')
    parser.add_argument('route53_json', help='Route53 configuration JSON file')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    args = parser.parse_args()

    try:
        print("AWS Security Configuration Correlator")
        print("=" * 50)

        # 创建关联分析器
        correlator = SecurityConfigCorrelator(
            args.waf_json,
            args.alb_json,
            args.route53_json,
            debug=args.debug
        )

        # 执行关联分析
        correlator.correlate_waf_alb()
        correlator.correlate_route53_alb()

        # 检测安全问题
        unprotected = correlator.detect_unprotected_albs()
        orphans = correlator.detect_orphan_dns_records()
        unused = correlator.detect_unused_waf_acls()

        # 生成统计
        stats = correlator.generate_statistics()

        # 输出摘要
        print("\n" + "=" * 50)
        print("Summary:")
        print(f"  WAF Coverage: {stats['waf_coverage_rate']}%")
        print(f"  Unprotected Public ALBs: {len(unprotected)}")
        print(f"  Orphan DNS Records: {len(orphans)}")
        print(f"  Unused WAF ACLs: {len(unused)}")

        if correlator.warnings:
            print(f"\n⚠️  Warnings: {len(correlator.warnings)}")
            for warning in correlator.warnings[:5]:  # 只显示前 5 个
                print(f"    - {warning['message']}")

        print("\n✓ Analysis complete")

    except Exception as e:
        print(f"\n✗ Error: {e}", file=sys.stderr)
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
