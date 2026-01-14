#!/usr/bin/env python3
"""
AWS Multi-Account Route53 Configuration Extractor

从多个 AWS member account 中获取 Route53 Hosted Zone 和 DNS Records 配置
使用 AWS Identity Center (SSO) 进行认证

注意: Route53 是全局服务，不区分区域
"""

import boto3
import json
import os
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import argparse
from botocore.exceptions import ClientError


def load_config_file(config_path: str = 'route53_scan_config.json') -> Optional[Dict]:
    """
    从配置文件加载扫描配置（支持独立配置文件和统一配置文件）

    Args:
        config_path: 配置文件路径

    Returns:
        配置字典，如果文件不存在则返回 None
    """
    # 优先尝试独立配置文件（向后兼容）
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            return config
        except Exception as e:
            print(f"⚠️  警告: 无法读取配置文件 {config_path}: {str(e)}")

    # 尝试统一配置文件
    unified_config_path = 'aws_multi_account_scan_config.json'
    if os.path.exists(unified_config_path):
        try:
            with open(unified_config_path, 'r', encoding='utf-8') as f:
                unified_config = json.load(f)

            # 提取 route53 特定配置，并合并公共配置
            if 'route53' in unified_config:
                config = {
                    'profiles': unified_config.get('profiles', []),
                    'regions': unified_config.get('regions', {}),
                    'scan_options': unified_config['route53'].get('scan_options', {}),
                    'filters': unified_config['route53'].get('filters', {})
                }
                print(f"✓ 使用统一配置文件: {unified_config_path}")
                return config
        except Exception as e:
            print(f"⚠️  警告: 无法读取统一配置文件 {unified_config_path}: {str(e)}")

    return None


class Route53ConfigExtractor:
    """Route53 配置提取器"""

    # Route53 是全局服务，固定使用 us-east-1 作为客户端区域
    CLIENT_REGION = 'us-east-1'

    def __init__(self, profile_names: List[str], regions: Optional[List[str]] = None,
                 debug: bool = False):
        """
        初始化提取器

        Args:
            profile_names: SSO profile 名称列表
            regions: 区域列表（Route53 是全局服务，此参数会被忽略但保留接口兼容性）
            debug: 是否启用调试模式

        注意: 只扫描 Public Hosted Zones（Global level），不扫描 Private Zones（VPC level）
        """
        self.profile_names = profile_names
        self.results = []
        self.debug = debug

        # regions 参数被忽略，但保留以兼容配置文件
        if regions and debug:
            print(f"⚠️  Route53 是全局服务，regions 参数已被忽略: {regions}")

    def get_account_info(self, session: boto3.Session) -> Dict[str, str]:
        """获取账户信息"""
        try:
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            return {
                'account_id': identity['Account'],
                'arn': identity['Arn'],
                'user_id': identity['UserId']
            }
        except Exception as e:
            return {'error': str(e)}

    def parse_routing_policy(self, record: Dict) -> Dict[str, Any]:
        """
        解析 DNS 记录的路由策略

        Args:
            record: Route53 API 返回的记录对象

        Returns:
            路由策略信息字典
        """
        policy_info = {
            'Type': 'Simple',  # 默认
            'Details': {}
        }

        # Weighted（加权）
        if record.get('Weight') is not None:
            policy_info['Type'] = 'Weighted'
            policy_info['Details']['Weight'] = record['Weight']

        # Latency（延迟）
        if record.get('Region'):
            policy_info['Type'] = 'Latency'
            policy_info['Details']['Region'] = record['Region']

        # Failover（故障转移）
        if record.get('Failover'):
            policy_info['Type'] = 'Failover'
            policy_info['Details']['Failover'] = record['Failover']  # PRIMARY 或 SECONDARY

        # Geolocation（地理位置）
        if record.get('GeoLocation'):
            policy_info['Type'] = 'Geolocation'
            policy_info['Details']['GeoLocation'] = record['GeoLocation']

        # Geoproximity（地理邻近，需要 Traffic Flow）
        if record.get('GeoProximityLocation'):
            policy_info['Type'] = 'Geoproximity'
            policy_info['Details']['GeoProximityLocation'] = record['GeoProximityLocation']

        # Multivalue Answer（多值应答）
        if record.get('MultiValueAnswer'):
            policy_info['Type'] = 'Multivalue'

        # SetIdentifier 用于区分相同名称和类型的记录
        if record.get('SetIdentifier'):
            policy_info['SetIdentifier'] = record['SetIdentifier']

        return policy_info

    def parse_alias_target(self, alias_target: Dict) -> Dict[str, Any]:
        """
        解析 Alias 记录的目标（不递归解析，只推断目标类型）

        Args:
            alias_target: AliasTarget 对象

        Returns:
            Alias 目标信息
        """
        dns_name_value = alias_target.get('DNSName', '')

        alias_info = {
            'DNSName': dns_name_value,
            'HostedZoneId': alias_target.get('HostedZoneId'),
            'EvaluateTargetHealth': alias_target.get('EvaluateTargetHealth'),
        }

        # 尝试推断目标类型（基于 DNS 名称模式）
        dns_name = dns_name_value.lower() if dns_name_value else ''

        if 'elb.amazonaws.com' in dns_name or 'elasticloadbalancing' in dns_name:
            alias_info['TargetType'] = 'ELB (Application/Network/Classic Load Balancer)'
        elif 'cloudfront.net' in dns_name:
            alias_info['TargetType'] = 'CloudFront Distribution'
        elif 's3-website' in dns_name:
            alias_info['TargetType'] = 'S3 Website Endpoint'
        elif 'execute-api' in dns_name:
            alias_info['TargetType'] = 'API Gateway'
        elif 'amplifyapp.com' in dns_name:
            alias_info['TargetType'] = 'AWS Amplify'
        elif 'apprunner' in dns_name:
            alias_info['TargetType'] = 'App Runner'
        else:
            alias_info['TargetType'] = 'Unknown (possibly another Route53 record)'

        return alias_info

    def get_zone_records(self, session: boto3.Session, zone_id: str, zone_name: str) -> List[Dict]:
        """
        获取 Hosted Zone 的所有 DNS 记录（支持分页和限流重试）

        Args:
            session: boto3 会话
            zone_id: Hosted Zone ID（例如 Z1234567890ABC）
            zone_name: Zone 名称（用于日志）

        Returns:
            DNS 记录列表
        """
        route53 = session.client('route53', region_name=self.CLIENT_REGION)

        records = []
        max_retries = 3
        retry_delay = 2  # 秒

        try:
            # 使用 paginator 自动处理分页（最多 300 条/页）
            paginator = route53.get_paginator('list_resource_record_sets')

            for page in paginator.paginate(HostedZoneId=zone_id):
                for record in page.get('ResourceRecordSets', []):
                    # 解析路由策略
                    routing_policy = self.parse_routing_policy(record)

                    # 解析 Alias 记录
                    alias_info = None
                    if record.get('AliasTarget'):
                        alias_info = self.parse_alias_target(record['AliasTarget'])

                    # 构建记录信息
                    record_info = {
                        'Name': record.get('Name'),
                        'Type': record.get('Type'),
                        'TTL': record.get('TTL'),  # Alias 记录没有 TTL
                        'ResourceRecords': record.get('ResourceRecords', []),
                        'AliasTarget': alias_info,
                        'RoutingPolicy': routing_policy,
                        'HealthCheckId': record.get('HealthCheckId'),
                        'SetIdentifier': record.get('SetIdentifier'),
                    }

                    records.append(record_info)

            if self.debug:
                print(f"      [DEBUG] 获取到 {len(records)} 条 DNS 记录")

        except ClientError as e:
            if e.response['Error']['Code'] == 'Throttling':
                # API 限流，重试
                retry_count = 0
                while retry_count < max_retries:
                    retry_count += 1
                    wait_time = retry_delay * (2 ** (retry_count - 1))  # 指数退避
                    print(f"    ⚠️  API 限流，{wait_time} 秒后重试 ({retry_count}/{max_retries})...")
                    time.sleep(wait_time)

                    try:
                        return self.get_zone_records(session, zone_id, zone_name)
                    except Exception:
                        if retry_count >= max_retries:
                            print(f"    ✗ 超过最大重试次数，跳过 Zone: {zone_name}")
                            break
            else:
                print(f"    ✗ 获取 DNS 记录失败: {str(e)}")
        except Exception as e:
            print(f"    ✗ 获取 DNS 记录失败: {str(e)}")
            if self.debug:
                import traceback
                traceback.print_exc()

        return records

    def _summarize_record_types(self, records: List[Dict]) -> Dict[str, int]:
        """
        统计记录类型分布

        Args:
            records: DNS 记录列表

        Returns:
            记录类型统计字典
        """
        summary = defaultdict(int)
        for record in records:
            record_type = record.get('Type', 'Unknown')
            summary[record_type] += 1
        return dict(summary)

    def get_zone_details(self, session: boto3.Session, zone_id: str) -> Dict[str, Any]:
        """
        获取 Hosted Zone 的详细信息

        Args:
            session: boto3 会话
            zone_id: Hosted Zone ID

        Returns:
            Zone 详细信息
        """
        route53 = session.client('route53', region_name=self.CLIENT_REGION)

        try:
            response = route53.get_hosted_zone(Id=zone_id)

            zone_detail = {
                'HostedZone': response.get('HostedZone'),
                'DelegationSet': response.get('DelegationSet')  # NS 记录
            }

            return zone_detail

        except Exception as e:
            if self.debug:
                print(f"    [DEBUG] 获取 Zone 详情失败: {str(e)}")
            return {}

    def scan_hosted_zones(self, session: boto3.Session) -> List[Dict]:
        """
        扫描所有 Hosted Zones（支持分页）

        Args:
            session: boto3 会话

        Returns:
            Hosted Zones 列表
        """
        route53 = session.client('route53', region_name=self.CLIENT_REGION)

        zones = []

        try:
            # 使用 paginator 处理大量 Zone
            paginator = route53.get_paginator('list_hosted_zones')

            for page in paginator.paginate():
                for zone in page.get('HostedZones', []):
                    zone_id = zone['Id']
                    zone_name = zone['Name']
                    is_private = zone['Config'].get('PrivateZone', False)

                    # 只扫描 Public Zones，跳过 Private Zones
                    if is_private:
                        if self.debug:
                            print(f"    ⊘ 跳过私有 Zone (VPC level): {zone_name}")
                        continue

                    if self.debug:
                        print(f"    处理公有 Zone: {zone_name} ({zone_id})")
                    else:
                        print(f"    扫描公有 Zone: {zone_name}")

                    # 获取详细信息
                    zone_details = self.get_zone_details(session, zone_id)

                    # 获取 DNS 记录
                    records = self.get_zone_records(session, zone_id, zone_name)

                    # 构建结果
                    zone_info = {
                        'basic_info': zone,
                        'delegation_set': zone_details.get('DelegationSet'),
                        'records': records,
                        'record_count': len(records),
                        'record_type_summary': self._summarize_record_types(records)
                    }

                    zones.append(zone_info)

        except Exception as e:
            print(f"  ✗ 扫描 Hosted Zones 失败: {str(e)}")
            if self.debug:
                import traceback
                traceback.print_exc()

        return zones

    def scan_account(self, profile_name: str) -> Dict[str, Any]:
        """
        扫描单个账户

        Args:
            profile_name: AWS SSO profile 名称

        Returns:
            账户扫描结果
        """
        print(f"\n{'='*80}")
        print(f"扫描账户: {profile_name}")
        print(f"{'='*80}")

        try:
            # 创建会话
            session = boto3.Session(profile_name=profile_name)

            # 获取账户信息
            account_info = self.get_account_info(session)
            account_id = account_info.get('account_id', 'Unknown')

            print(f"账户 ID: {account_id}")
            print(f"ARN: {account_info.get('arn', 'Unknown')}")

            if 'error' in account_info:
                raise Exception(f"无法获取账户信息: {account_info['error']}")

            # 扫描 Hosted Zones（Route53 是全局服务，不需要区域循环）
            print(f"\n正在扫描 Hosted Zones...")
            zones = self.scan_hosted_zones(session)

            # 统计信息（只包含 Public Zones）
            total_zones = len(zones)
            total_records = sum(z['record_count'] for z in zones)

            summary = {
                'total_public_zones': total_zones,
                'total_records': total_records
            }

            print(f"\n✓ 扫描完成:")
            print(f"  - 公有 Hosted Zones: {total_zones}")
            print(f"  - 总 DNS 记录: {total_records}")

            # 构建账户结果
            account_result = {
                'profile': profile_name,
                'account_info': account_info,
                'scan_time': datetime.now(timezone.utc).isoformat(),
                'hosted_zones': zones,
                'summary': summary
            }

            return account_result

        except Exception as e:
            print(f"✗ 扫描账户 {profile_name} 失败: {str(e)}")
            if self.debug:
                import traceback
                traceback.print_exc()

            return {
                'profile': profile_name,
                'account_info': {'error': str(e)},
                'scan_time': datetime.now(timezone.utc).isoformat(),
                'hosted_zones': [],
                'summary': {
                    'total_public_zones': 0,
                    'total_records': 0
                }
            }

    def scan_all_accounts(self, parallel: bool = True) -> List[Dict]:
        """
        扫描所有账户

        Args:
            parallel: 是否并行扫描（账户级别）

        Returns:
            所有账户的扫描结果
        """
        if parallel and len(self.profile_names) > 1:
            # 并行扫描多个账户
            print(f"使用并行模式扫描 {len(self.profile_names)} 个账户（最多 3 个并发）")

            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = {
                    executor.submit(self.scan_account, profile): profile
                    for profile in self.profile_names
                }

                for future in as_completed(futures):
                    try:
                        result = future.result()
                        self.results.append(result)
                    except Exception as e:
                        profile = futures[future]
                        print(f"✗ 扫描账户 {profile} 失败: {str(e)}")
        else:
            # 串行扫描
            for profile in self.profile_names:
                result = self.scan_account(profile)
                self.results.append(result)

        return self.results

    def save_results(self, output_file: Optional[str] = None):
        """
        保存结果到 JSON 文件

        Args:
            output_file: 输出文件名，如果为 None 则自动生成
        """
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f'route53_config_{timestamp}.json'

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)

            print(f"\n{'='*80}")
            print(f"✓ 结果已保存到: {output_file}")
            print(f"{'='*80}")
        except Exception as e:
            print(f"✗ 保存结果失败: {str(e)}")

    def print_summary(self):
        """打印总体统计摘要（只包含 Public Zones）"""
        if not self.results:
            return

        total_public_zones = 0
        total_records = 0

        for account in self.results:
            summary = account.get('summary', {})
            total_public_zones += summary.get('total_public_zones', 0)
            total_records += summary.get('total_records', 0)

        print(f"\n{'='*80}")
        print(f"总体统计")
        print(f"{'='*80}")
        print(f"扫描账户数: {len(self.results)}")
        print(f"公有 Hosted Zones: {total_public_zones}")
        print(f"总 DNS 记录: {total_records}")


def main():
    parser = argparse.ArgumentParser(
        description='从多个 AWS 账户中提取 Route53 Hosted Zone 和 DNS Records 配置'
    )

    parser.add_argument('-p', '--profiles',
                        nargs='+',
                        help='AWS SSO profile 名称（可指定多个）')

    parser.add_argument('-r', '--regions',
                        nargs='+',
                        help='AWS 区域列表（Route53 是全局服务，此参数会被忽略但保留接口兼容性）')

    parser.add_argument('--debug',
                        action='store_true',
                        help='启用调试模式')

    parser.add_argument('--no-parallel',
                        action='store_true',
                        help='禁用并行扫描（串行处理所有账户）')

    parser.add_argument('-o', '--output',
                        help='指定输出文件名（默认自动生成）')

    args = parser.parse_args()

    # 加载配置文件
    config = load_config_file()

    # 确定 profiles
    profiles = args.profiles
    if not profiles and config:
        profiles = config.get('profiles', [])

    if not profiles:
        print("错误: 必须提供至少一个 AWS profile")
        print("  方式1: 使用 -p 参数指定")
        print("  方式2: 在 route53_scan_config.json 中配置")
        return

    # 确定 regions（虽然会被忽略）
    regions = args.regions
    if not regions and config:
        region_config = config.get('regions', {})
        regions = region_config.get('common', [])

    # 创建提取器（只扫描 Public Zones）
    extractor = Route53ConfigExtractor(
        profile_names=profiles,
        regions=regions,
        debug=args.debug
    )

    # 扫描所有账户
    parallel = not args.no_parallel
    if config and 'scan_options' in config:
        parallel = config['scan_options'].get('parallel', parallel)

    extractor.scan_all_accounts(parallel=parallel)

    # 打印总体统计
    extractor.print_summary()

    # 保存结果
    extractor.save_results(args.output)


if __name__ == '__main__':
    main()
