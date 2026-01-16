#!/usr/bin/env python3
"""
AWS Security Configuration Visualizer

将关联分析结果生成交互式 HTML 可视化报告。
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from jinja2 import Environment, FileSystemLoader, select_autoescape


class SecurityVisualizer:
    """安全配置可视化生成器"""

    def __init__(self, correlator, debug: bool = False):
        """
        初始化可视化生成器

        Args:
            correlator: SecurityConfigCorrelator 实例
            debug: 是否启用调试模式
        """
        self.correlator = correlator
        self.debug = debug

        # 设置 Jinja2 环境
        template_dir = Path(__file__).parent / 'templates'
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(['html'])
        )

    def generate_network_graph_data(self) -> Dict:
        """生成网络图数据（D3.js 兼容格式）"""
        if self.debug:
            print("Generating network graph data...")

        graph = self.correlator.build_graph()

        nodes = []
        for node_id, attrs in graph.nodes(data=True):
            nodes.append({
                'id': node_id,
                'type': attrs.get('type', 'unknown'),
                'label': attrs.get('label', 'unknown'),
                'color': attrs.get('color', '#999'),
                'details': attrs.get('details', {})
            })

        edges = []
        for source, target, attrs in graph.edges(data=True):
            edges.append({
                'source': source,
                'target': target,
                'label': attrs.get('label', '')
            })

        return {
            'nodes': nodes,
            'edges': edges
        }

    def generate_tree_data(self) -> Dict:
        """生成层级树状图数据"""
        if self.debug:
            print("Generating tree diagram data...")

        tree = {
            'name': 'AWS Resources',
            'children': []
        }

        # 按账户分组
        for account_id in sorted(self.correlator.accounts):
            account_node = {
                'name': f'Account {account_id}',
                'children': []
            }

            # 按区域分组
            for region in sorted(self.correlator.regions):
                # 获取该账户和区域的资源
                region_albs = [alb for alb in self.correlator.alb_arn_index.values()
                              if alb.get('account_id') == account_id and alb.get('region') == region]
                region_wafs = [waf for waf in self.correlator.waf_arn_index.values()
                              if waf.get('account_id') == account_id and waf.get('region') == region]

                if not region_albs and not region_wafs:
                    continue

                region_node = {
                    'name': region,
                    'children': []
                }

                # ALBs
                if region_albs:
                    alb_category = {
                        'name': f'ALBs ({len(region_albs)})',
                        'children': []
                    }
                    for alb in region_albs:
                        alb_name = self.correlator.safe_get(alb, 'basic_info.LoadBalancerName', 'unknown')
                        has_waf = self.correlator.safe_get(alb, 'waf_association.has_waf', False)
                        alb_category['children'].append({
                            'name': f"{alb_name} {'🛡️' if has_waf else '⚠️'}"
                        })
                    region_node['children'].append(alb_category)

                # WAF ACLs
                if region_wafs:
                    waf_category = {
                        'name': f'WAF ACLs ({len(region_wafs)})',
                        'children': []
                    }
                    for waf in region_wafs:
                        waf_name = waf.get('summary', {}).get('Name') or waf.get('detail', {}).get('Name', 'unknown')
                        waf_category['children'].append({
                            'name': waf_name
                        })
                    region_node['children'].append(waf_category)

                account_node['children'].append(region_node)

            if account_node['children']:
                tree['children'].append(account_node)

        return tree

    def generate_dashboard_data(self) -> Dict:
        """生成统计仪表盘数据"""
        if self.debug:
            print("Generating dashboard data...")

        stats = self.correlator.generate_statistics()

        return {
            'waf_coverage': {
                'protected': stats['albs_with_waf'],
                'unprotected': stats['albs_without_waf'],
                'coverage_rate': stats['waf_coverage_rate']
            },
            'by_account': stats['by_account'],
            'by_region': stats['by_region'],
            'by_type': stats['by_type'],
            'summary': {
                'total_albs': stats['total_albs'],
                'total_wafs': stats['total_wafs'],
                'total_dns_records': stats['total_dns_records']
            }
        }

    def generate_vulnerability_table(self) -> List[Dict]:
        """生成安全漏洞列表数据"""
        if self.debug:
            print("Generating vulnerability table data...")

        vulnerabilities = []

        # 未保护的 ALB
        for vuln in self.correlator.unprotected_albs:
            vulnerabilities.append(vuln)

        # 孤儿 DNS 记录
        for vuln in self.correlator.orphan_dns_records:
            vulnerabilities.append(vuln)

        # 未使用的 WAF ACL
        for vuln in self.correlator.unused_waf_acls:
            vulnerabilities.append(vuln)

        return vulnerabilities

    def render_html(self, output_file: str):
        """渲染 HTML 报告"""
        if self.debug:
            print(f"\nRendering HTML report to: {output_file}")

        try:
            # 生成所有数据
            network_graph_data = self.generate_network_graph_data()
            tree_data = self.generate_tree_data()
            dashboard_data = self.generate_dashboard_data()
            vulnerabilities_data = self.generate_vulnerability_table()

            # 读取 JavaScript 和 CSS 文件
            template_dir = Path(__file__).parent / 'templates'
            network_graph_js = (template_dir / 'network_graph.js').read_text()
            tree_diagram_js = (template_dir / 'tree_diagram.js').read_text()
            dashboard_charts_js = (template_dir / 'dashboard_charts.js').read_text()
            styles_css = (template_dir / 'styles.css').read_text()

            # 渲染模板
            template = self.env.get_template('report_template.html')
            html_content = template.render(
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                network_graph_data=network_graph_data,
                tree_data=tree_data,
                dashboard_data=dashboard_data,
                vulnerabilities_data=vulnerabilities_data,
                network_graph_js=network_graph_js,
                tree_diagram_js=tree_diagram_js,
                dashboard_charts_js=dashboard_charts_js,
                styles_css=styles_css,
                warnings=self.correlator.warnings
            )

            # 写入文件
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)

            if self.debug:
                print("✓ HTML report generated successfully")

        except Exception as e:
            print(f"✗ Error generating HTML report: {e}")
            raise

    def save_json_data(self, output_file: str):
        """保存 JSON 数据（用于调试）"""
        if self.debug:
            print(f"Saving JSON data to: {output_file}")

        data = {
            'timestamp': datetime.now().isoformat(),
            'network_graph': self.generate_network_graph_data(),
            'tree_diagram': self.generate_tree_data(),
            'dashboard': self.generate_dashboard_data(),
            'vulnerabilities': self.generate_vulnerability_table(),
            'warnings': self.correlator.warnings,
            'statistics': self.correlator.generate_statistics()
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        if self.debug:
            print("✓ JSON data saved successfully")


def main():
    """主程序（用于测试）"""
    import argparse
    from correlate_security_config import SecurityConfigCorrelator

    parser = argparse.ArgumentParser(description='AWS Security Configuration Visualizer')
    parser.add_argument('waf_json', help='WAF configuration JSON file')
    parser.add_argument('alb_json', help='ALB configuration JSON file')
    parser.add_argument('route53_json', help='Route53 configuration JSON file')
    parser.add_argument('-o', '--output', help='Output HTML file',
                       default=f"security_audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    parser.add_argument('--json', action='store_true', help='Also output JSON data file')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    args = parser.parse_args()

    try:
        print("AWS Security Configuration Visualizer")
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
        correlator.detect_unprotected_albs()
        correlator.detect_unused_waf_acls()

        # 创建可视化生成器
        visualizer = SecurityVisualizer(correlator, debug=args.debug)

        # 生成 HTML 报告
        visualizer.render_html(args.output)
        print(f"\n✓ Report generated: {args.output}")

        # 可选：输出 JSON
        if args.json:
            json_output = args.output.replace('.html', '.json')
            visualizer.save_json_data(json_output)
            print(f"✓ Data saved: {json_output}")

    except Exception as e:
        print(f"\n✗ Error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        import sys
        sys.exit(1)


if __name__ == '__main__':
    main()
