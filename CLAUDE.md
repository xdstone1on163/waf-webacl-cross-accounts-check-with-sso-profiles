# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

AWS 多账户 WAF 配置提取和分析工具集。从多个 AWS member accounts 中自动提取 WAF v2 Web ACL 配置，支持 AWS SSO 认证，并提供分析和可视化功能。

## 核心架构

### 三层工具结构

```
waf_scan.sh (交互式入口)
    ↓ 调用
get_waf_config.py (核心提取器)
    ↓ 生成 JSON
analyze_waf_config.py (分析器)
```

### 关键组件

1. **WAFConfigExtractor** (`get_waf_config.py`):
   - 使用 boto3 与 AWS WAFv2 API 交互
   - 支持并行扫描多账户/多区域（`ThreadPoolExecutor`）
   - CloudFront scope 只在 `us-east-1` 扫描（全局资源）
   - Regional scope 在所有指定区域扫描
   - 自动解析资源 ARN，提取 friendly_type 和 resource_id

2. **WAFConfigAnalyzer** (`analyze_waf_config.py`):
   - 解析 JSON 输出
   - 生成规则统计、资源类型分布、CSV 导出
   - 支持搜索和过滤功能

3. **交互式扫描器** (`waf_scan.sh`):
   - 环境检查（Python、boto3、AWS CLI）
   - SSO 登录状态验证
   - 菜单驱动的用户界面

### 配置文件结构

- `waf_scan_config.json`: 扫描配置（profiles、regions、scan_options）
- `waf_scan_config.json.example`: 示例模板
- **注意**: `waf_config_*.json` 包含敏感信息，已在 `.gitignore` 中

## 常用命令

### 基础扫描

```bash
# 推荐：使用交互式脚本（新用户）
./waf_scan.sh

# 使用配置文件扫描
python3 get_waf_config.py

# 指定单个账户
python3 get_waf_config.py -p AdministratorAccess-275261018177

# 指定多个账户和区域
python3 get_waf_config.py -p profile1 profile2 -r us-east-1 us-west-2

# 调试模式
python3 get_waf_config.py --debug

# 串行模式（禁用并行）
python3 get_waf_config.py --no-parallel
```

### 分析结果

```bash
# 列出所有 Web ACL
python3 analyze_waf_config.py waf_config_20260107_171514.json --list

# 规则统计分析
python3 analyze_waf_config.py waf_config_20260107_171514.json --analyze

# 关联资源分析
python3 analyze_waf_config.py waf_config_20260107_171514.json --resources

# 搜索特定 ACL
python3 analyze_waf_config.py waf_config_20260107_171514.json --search "api"

# 导出为 CSV
python3 analyze_waf_config.py waf_config_20260107_171514.json --csv report.csv

# 综合分析（运行所有分析）
python3 analyze_waf_config.py waf_config_20260107_171514.json
```

### 调试工具

```bash
# 验证特定 Web ACL 的资源关联
./check_waf_resources.sh <profile-name> <web-acl-name>

# 示例
./check_waf_resources.sh AdministratorAccess-813923830882 waf-demo-juice-shop
```

### AWS SSO 认证

```bash
# 配置 SSO
aws configure sso

# 登录（扫描前必须）
aws sso login --profile AdministratorAccess-275261018177

# 检查登录状态
aws sts get-caller-identity --profile AdministratorAccess-275261018177
```

## 重要的代码模式

### CloudFront vs Regional Scope

- **CloudFront**: 全局资源，只需在 `us-east-1` 扫描
- **Regional**: 区域资源，每个指定区域都要扫描
- `get_waf_config.py:289-312` 中实现了 scope 特定的扫描逻辑

### 获取关联资源的实现

**CloudFront scope**（`get_waf_config.py:177-228`）:
- 使用 **CloudFront API** 而不是 WAFv2 API
- 调用 `cloudfront.list_distributions_by_web_acl_id(WebACLId=arn)`
- 从 CloudFront 服务直接查询，更可靠
- 额外提取 `distribution_domain` 和 `distribution_status` 字段

**Regional scope**（`get_waf_config.py:231-263`）:
- 使用 **WAFv2 API** `list_resources_for_web_acl`
- 遍历所有支持的资源类型（ALB、API Gateway、AppSync 等）
- 每种资源类型单独查询

### 资源 ARN 解析

ARN 格式: `arn:partition:service:region:account-id:resource-type/resource-id`

关键映射关系（`get_waf_config.py:124-148`）:
- `elasticloadbalancing` + `loadbalancer/app` → Application Load Balancer
- `cloudfront` + `distribution` → CloudFront Distribution
- `apigateway` + `restapis` → REST API
- `cognito-idp` + `userpool` → Cognito User Pool

### 已知问题修复

- **CloudFront distribution 关联**: 使用 CloudFront API `list_distributions_by_web_acl_id` 替代 WAFv2 API，解决无法获取关联的问题
- **Managed Rule Groups 动作显示**: commit `5247b73` 修复了动作显示为 "Unknown" 的问题
- **CloudFront 区域发现**: commit `9fca584` 修复了 CloudFront WebACL 必须在 us-east-1 扫描的问题

## 必需的 IAM 权限

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "wafv2:ListWebACLs",
        "wafv2:GetWebACL",
        "wafv2:ListResourcesForWebACL",
        "cloudfront:ListDistributionsByWebACLId",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

**新增权限说明**:
- `cloudfront:ListDistributionsByWebACLId` - 获取与 WAF ACL 关联的 CloudFront distributions（2026-01-08 新增）

## 安全注意事项

输出的 JSON 文件包含敏感信息：
- AWS 账户 ID
- 资源 ARN（包含账户、区域、资源 ID）
- Web ACL 配置详情

**不要提交到 Git！** `.gitignore` 已配置忽略 `waf_config_*.json` 和 `*.csv`。

## 最近改动

- 2026-01-08: 修复 CloudFront distribution 关联获取问题，使用 CloudFront API 替代 WAFv2 API
- 2026-01-08: 修复 datetime.utcnow() deprecation warning
- 2026-01-08 (commit 3c318a1): 添加项目级 CLAUDE.md 文档
- 2026-01-07 (commit 612b769): 删除安全检查相关文件，简化项目结构
- 2026-01-07 (commit 5247b73): 修复 Managed Rule Groups 动作显示为 Unknown 的问题
- 2026-01-06 (commit b233d72): 改进规则显示功能
- 2026-01-06 (commit bc5fc8e): 整合和优化脚本结构，更新文档
- 2026-01-05 (commit 9fca584): 修复 CloudFront WebACL 发现问题（现在区域独立）
