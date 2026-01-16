#!/usr/bin/env python3
"""
AWS Multi-Account ALB Configuration Extractor

从多个 AWS member account 中获取 Application Load Balancer 配置
使用 AWS Identity Center (SSO) 进行认证
"""

import boto3
import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
from core.file_utils import save_scan_results


def load_config_file(config_path: str = 'alb_scan_config.json') -> Optional[Dict]:
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

            # 提取 alb 特定配置，并合并公共配置
            if 'alb' in unified_config:
                config = {
                    'profiles': unified_config.get('profiles', []),
                    'regions': unified_config.get('regions', {}),
                    'scan_options': unified_config['alb'].get('scan_options', {}),
                    'filters': unified_config['alb'].get('filters', {})
                }
                print(f"✓ 使用统一配置文件: {unified_config_path}")
                return config
        except Exception as e:
            print(f"⚠️  警告: 无法读取统一配置文件 {unified_config_path}: {str(e)}")

    return None


class ALBConfigExtractor:
    """ALB 配置提取器"""

    # 常用的 AWS 区域列表
    COMMON_REGIONS = [
        'us-east-1',      # 美东（弗吉尼亚北部）
        'us-west-2',      # 美西（俄勒冈）
        'ap-northeast-1', # 亚太（东京）
        'ap-southeast-1', # 亚太（新加坡）
        'eu-west-1',      # 欧洲（爱尔兰）
        'eu-central-1',   # 欧洲（法兰克福）
    ]

    def __init__(self, profile_names: List[str], regions: List[str] = None,
                 scan_mode: str = 'standard', debug: bool = False):
        """
        初始化提取器

        Args:
            profile_names: SSO profile 名称列表
            regions: 要扫描的区域列表，默认使用 COMMON_REGIONS
            scan_mode: 扫描模式 ('quick', 'standard', 'full')
            debug: 是否启用调试模式
        """
        self.profile_names = profile_names
        self.regions = regions or self.COMMON_REGIONS
        self.scan_mode = scan_mode
        self.results = []
        self.debug = debug

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

    def parse_alb_type(self, type_string: str) -> str:
        """
        解析 ALB 类型为友好名称

        Args:
            type_string: AWS API 返回的类型 ('application', 'network', 'gateway')

        Returns:
            友好的类型名称
        """
        type_mapping = {
            'application': 'Application Load Balancer',
            'network': 'Network Load Balancer',
            'gateway': 'Gateway Load Balancer'
        }
        return type_mapping.get(type_string, type_string)

    def get_waf_association(self, session: boto3.Session, alb_arn: str, region: str) -> Dict[str, Any]:
        """
        获取 ALB 关联的 WAF Web ACL

        Args:
            session: boto3 会话
            alb_arn: ALB 的 ARN
            region: AWS 区域

        Returns:
            WAF 关联信息字典
        """
        try:
            if self.debug:
                print(f"      [DEBUG] 查询 WAF 关联: {alb_arn}")

            wafv2 = session.client('wafv2', region_name=region)
            response = wafv2.get_web_acl_for_resource(ResourceArn=alb_arn)

            web_acl = response.get('WebACL', {})
            if self.debug:
                print(f"      [DEBUG] 找到 WAF: {web_acl.get('Name', 'Unknown')}")

            return {
                'has_waf': True,
                'WebACL': web_acl
            }
        except wafv2.exceptions.WAFNonexistentItemException:
            # 没有关联 WAF 是正常情况
            if self.debug:
                print(f"      [DEBUG] 未关联 WAF")
            return {'has_waf': False, 'WebACL': None}
        except Exception as e:
            if self.debug:
                print(f"      [DEBUG] 查询 WAF 失败: {str(e)}")
            return {'has_waf': False, 'error': str(e)}

    def get_security_groups(self, ec2_client, sg_ids: List[str]) -> List[Dict]:
        """
        获取安全组详情

        Args:
            ec2_client: EC2 客户端
            sg_ids: 安全组 ID 列表

        Returns:
            安全组详情列表
        """
        if not sg_ids:
            return []

        try:
            response = ec2_client.describe_security_groups(GroupIds=sg_ids)
            return response.get('SecurityGroups', [])
        except Exception as e:
            if self.debug:
                print(f"      [DEBUG] 获取安全组失败: {str(e)}")
            return []

    def get_alb_listeners(self, elbv2_client, alb_arn: str) -> List[Dict]:
        """
        获取 ALB 监听器配置

        Args:
            elbv2_client: ELBv2 客户端
            alb_arn: ALB ARN

        Returns:
            监听器列表
        """
        try:
            response = elbv2_client.describe_listeners(LoadBalancerArn=alb_arn)
            return response.get('Listeners', [])
        except Exception as e:
            if self.debug:
                print(f"      [DEBUG] 获取监听器失败: {str(e)}")
            return []

    def get_listener_rules(self, elbv2_client, listener_arn: str) -> List[Dict]:
        """
        获取监听器转发规则

        Args:
            elbv2_client: ELBv2 客户端
            listener_arn: 监听器 ARN

        Returns:
            规则列表
        """
        try:
            response = elbv2_client.describe_rules(ListenerArn=listener_arn)
            return response.get('Rules', [])
        except Exception as e:
            if self.debug:
                print(f"      [DEBUG] 获取监听器规则失败: {str(e)}")
            return []

    def get_target_groups(self, elbv2_client, alb_arn: str) -> List[Dict]:
        """
        获取目标组配置

        Args:
            elbv2_client: ELBv2 客户端
            alb_arn: ALB ARN

        Returns:
            目标组列表
        """
        try:
            response = elbv2_client.describe_target_groups(LoadBalancerArn=alb_arn)
            return response.get('TargetGroups', [])
        except Exception as e:
            if self.debug:
                print(f"      [DEBUG] 获取目标组失败: {str(e)}")
            return []

    def get_target_health(self, elbv2_client, target_group_arn: str) -> List[Dict]:
        """
        获取目标健康状态

        Args:
            elbv2_client: ELBv2 客户端
            target_group_arn: 目标组 ARN

        Returns:
            目标健康状态列表
        """
        try:
            response = elbv2_client.describe_target_health(TargetGroupArn=target_group_arn)
            return response.get('TargetHealthDescriptions', [])
        except Exception as e:
            if self.debug:
                print(f"      [DEBUG] 获取目标健康状态失败: {str(e)}")
            return []

    def get_alb_details(self, session: boto3.Session, alb: Dict, region: str) -> Dict[str, Any]:
        """
        获取单个 ALB 的详细信息

        Args:
            session: boto3 会话
            alb: describe_load_balancers 返回的 ALB 信息
            region: AWS 区域

        Returns:
            ALB 详细信息字典
        """
        alb_arn = alb['LoadBalancerArn']
        alb_name = alb['LoadBalancerName']

        if self.debug:
            print(f"    [DEBUG] 处理 ALB: {alb_name}")

        # 基本信息
        alb_details = {
            'basic_info': {
                'LoadBalancerName': alb_name,
                'LoadBalancerArn': alb_arn,
                'DNSName': alb.get('DNSName'),
                'Type': alb.get('Type'),
                'FriendlyType': self.parse_alb_type(alb.get('Type', '')),
                'State': alb.get('State'),
                'CreatedTime': alb.get('CreatedTime').isoformat() if alb.get('CreatedTime') else None,
                'VpcId': alb.get('VpcId'),
                'Scheme': alb.get('Scheme'),
                'IpAddressType': alb.get('IpAddressType'),
                'AvailabilityZones': alb.get('AvailabilityZones', []),
                'SecurityGroups': alb.get('SecurityGroups', [])
            }
        }

        # WAF 关联（所有模式都获取）
        alb_details['waf_association'] = self.get_waf_association(session, alb_arn, region)

        # 创建客户端
        elbv2 = session.client('elbv2', region_name=region)

        # standard 和 full 模式获取更多信息
        if self.scan_mode in ['standard', 'full']:
            # 监听器
            listeners = self.get_alb_listeners(elbv2, alb_arn)
            alb_details['listeners'] = listeners

            # full 模式获取监听器规则
            if self.scan_mode == 'full' and listeners:
                for listener in listeners:
                    listener['Rules'] = self.get_listener_rules(elbv2, listener['ListenerArn'])

            # 目标组
            target_groups = self.get_target_groups(elbv2, alb_arn)
            alb_details['target_groups'] = target_groups

            # full 模式获取目标健康状态
            if self.scan_mode == 'full' and target_groups:
                for tg in target_groups:
                    tg['target_health'] = self.get_target_health(elbv2, tg['TargetGroupArn'])

            # 安全组详情
            if alb.get('SecurityGroups'):
                ec2 = session.client('ec2', region_name=region)
                alb_details['security_groups_detail'] = self.get_security_groups(
                    ec2, alb.get('SecurityGroups', [])
                )

        return alb_details

    def scan_region(self, session: boto3.Session, region: str) -> List[Dict]:
        """
        在指定区域扫描所有 ALB

        Args:
            session: boto3 会话
            region: AWS 区域

        Returns:
            ALB 列表
        """
        albs = []

        try:
            elbv2 = session.client('elbv2', region_name=region)

            # 列出所有负载均衡器
            paginator = elbv2.get_paginator('describe_load_balancers')

            for page in paginator.paginate():
                for alb in page.get('LoadBalancers', []):
                    # 可以根据配置过滤类型（application/network/gateway）
                    alb_type = alb.get('Type', '')

                    # 获取详细信息
                    alb_details = self.get_alb_details(session, alb, region)

                    # 打印摘要
                    waf_status = "有 WAF" if alb_details['waf_association']['has_waf'] else "无 WAF"
                    print(f"    ✓ {alb['LoadBalancerName']} ({self.parse_alb_type(alb_type)}, {waf_status})")

                    albs.append(alb_details)

        except Exception as e:
            print(f"    ✗ 扫描区域 {region} 失败: {str(e)}")
            if self.debug:
                import traceback
                traceback.print_exc()

        return albs

    def scan_account(self, profile_name: str) -> Dict[str, Any]:
        """
        扫描单个账户的所有区域

        Args:
            profile_name: AWS SSO profile 名称

        Returns:
            账户扫描结果字典
        """
        print(f"\n{'='*80}")
        print(f"正在扫描账户: {profile_name}")
        print(f"{'='*80}")

        account_result = {
            'profile': profile_name,
            'scan_time': datetime.now(timezone.utc).isoformat(),
            'scan_mode': self.scan_mode,
            'regions': []
        }

        try:
            # 创建会话
            session = boto3.Session(profile_name=profile_name)

            # 获取账户信息
            account_info = self.get_account_info(session)
            account_result['account_info'] = account_info

            if 'error' in account_info:
                print(f"✗ 无法获取账户信息: {account_info['error']}")
                return account_result

            print(f"✓ 账户 ID: {account_info['account_id']}")

            # 扫描所有区域
            for region in self.regions:
                print(f"\n  扫描区域: {region}")

                albs = self.scan_region(session, region)

                if albs:
                    region_result = {
                        'region': region,
                        'load_balancers': albs
                    }
                    account_result['regions'].append(region_result)

        except Exception as e:
            print(f"✗ 扫描账户失败: {str(e)}")
            if self.debug:
                import traceback
                traceback.print_exc()

        return account_result

    def scan_all_accounts(self, parallel: bool = True) -> List[Dict]:
        """
        扫描所有账户

        Args:
            parallel: 是否并行扫描

        Returns:
            所有账户的扫描结果
        """
        if parallel and len(self.profile_names) > 1:
            # 并行扫描
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

    def save_results(self, output_file: Optional[str] = None, save_latest: bool = True):
        """
        保存扫描结果到 JSON 文件

        Args:
            output_file: 输出文件名，如果为 None 则自动生成带时间戳的文件名
            save_latest: 是否同时保存固定名称的 latest 文件（默认 True）

        Returns:
            主输出文件名（带时间戳）
        """
        main_file, _ = save_scan_results(
            data=self.results,
            prefix='alb_config',
            output_file=output_file,
            save_latest=save_latest,
            verbose=True
        )
        return main_file

    def print_summary(self):
        """打印扫描摘要"""
        print(f"\n{'='*80}")
        print("扫描摘要")
        print(f"{'='*80}")

        total_albs = 0
        total_with_waf = 0
        total_without_waf = 0

        for account in self.results:
            account_id = account.get('account_info', {}).get('account_id', 'Unknown')
            profile = account.get('profile')

            if account.get('regions'):
                print(f"\n账户 {account_id} ({profile}):")

                for region_data in account['regions']:
                    region = region_data['region']
                    albs = region_data.get('load_balancers', [])
                    alb_count = len(albs)

                    with_waf = sum(1 for alb in albs if alb['waf_association']['has_waf'])
                    without_waf = alb_count - with_waf

                    print(f"  - {region}: {alb_count} 个 ALB ({with_waf} 个有 WAF, {without_waf} 个无 WAF)")

                    total_albs += alb_count
                    total_with_waf += with_waf
                    total_without_waf += without_waf

        waf_coverage = (total_with_waf / total_albs * 100) if total_albs > 0 else 0

        print(f"\n总计: {total_albs} 个 ALB, {total_with_waf} 个有 WAF ({waf_coverage:.1f}%), {total_without_waf} 个无 WAF ({100-waf_coverage:.1f}%)")


def main():
    parser = argparse.ArgumentParser(
        description='AWS Multi-Account ALB 配置提取工具',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('-p', '--profiles', nargs='+',
                       help='AWS SSO profile 名称列表')
    parser.add_argument('-r', '--regions', nargs='+',
                       help='要扫描的 AWS 区域列表')
    parser.add_argument('--mode', choices=['quick', 'standard', 'full'],
                       default='standard',
                       help='扫描模式 (quick: 基本+WAF, standard: +监听器+目标组, full: +规则+健康检查)')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('--debug', action='store_true', help='启用调试模式')
    parser.add_argument('--no-parallel', action='store_true', help='禁用并行扫描')
    parser.add_argument('--no-latest', action='store_true',
                        help='只生成带时间戳的文件，不生成 latest 文件')

    args = parser.parse_args()

    # 尝试从配置文件加载
    config = load_config_file()

    # 确定 profiles
    profiles = args.profiles
    if not profiles and config:
        profiles = config.get('profiles', [])

    if not profiles:
        print("错误: 未指定 AWS profiles")
        print("请使用 -p 参数指定，或在 alb_scan_config.json 中配置")
        return 1

    # 确定 regions
    regions = args.regions
    if not regions and config:
        region_config = config.get('regions', {})
        regions = region_config.get('common', ALBConfigExtractor.COMMON_REGIONS)
    elif not regions:
        regions = ALBConfigExtractor.COMMON_REGIONS

    print(f"✓ 从配置加载了 {len(profiles)} 个 AWS profiles")
    print(f"✓ 从配置加载了 {len(regions)} 个扫描区域")
    print(f"✓ 扫描模式: {args.mode}")

    print(f"\n开始扫描 {len(profiles)} 个账户...")
    print(f"扫描区域: {', '.join(regions)}")

    # 创建提取器
    extractor = ALBConfigExtractor(
        profile_names=profiles,
        regions=regions,
        scan_mode=args.mode,
        debug=args.debug
    )

    # 扫描所有账户
    extractor.scan_all_accounts(parallel=not args.no_parallel)

    # 打印摘要
    extractor.print_summary()

    # 保存结果
    extractor.save_results(args.output, save_latest=not args.no_latest)

    return 0


if __name__ == '__main__':
    exit(main())
