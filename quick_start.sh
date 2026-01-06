#!/bin/bash
# WAF 配置提取工具 - 快速开始脚本

set -e

echo "=========================================="
echo "AWS WAF 配置提取工具 - 环境检查"
echo "=========================================="
echo ""

# 检查 Python
echo "1. 检查 Python..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo "   ✓ $PYTHON_VERSION"
else
    echo "   ✗ Python 3 未安装"
    exit 1
fi

# 检查 boto3
echo ""
echo "2. 检查 boto3..."
if python3 -c "import boto3" 2>/dev/null; then
    BOTO3_VERSION=$(python3 -c "import boto3; print(boto3.__version__)")
    echo "   ✓ boto3 $BOTO3_VERSION"
else
    echo "   ✗ boto3 未安装"
    echo ""
    read -p "   是否现在安装 boto3? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        pip3 install boto3
        echo "   ✓ boto3 安装完成"
    else
        echo "   请手动安装: pip3 install boto3"
        exit 1
    fi
fi

# 检查 AWS CLI
echo ""
echo "3. 检查 AWS CLI..."
if command -v aws &> /dev/null; then
    AWS_VERSION=$(aws --version 2>&1)
    echo "   ✓ $AWS_VERSION"
else
    echo "   ✗ AWS CLI 未安装"
    echo "   请访问: https://aws.amazon.com/cli/"
    exit 1
fi

# 检查 AWS 配置
echo ""
echo "4. 检查 AWS 配置..."
if [ -f ~/.aws/config ]; then
    echo "   ✓ AWS 配置文件存在"

    # 列出 SSO profiles
    SSO_PROFILES=$(aws configure list-profiles 2>/dev/null | grep -i "administrator" || true)
    if [ -n "$SSO_PROFILES" ]; then
        echo "   ✓ 发现 SSO profiles:"
        echo "$SSO_PROFILES" | sed 's/^/     - /'
    else
        echo "   ! 未发现 SSO profiles"
    fi
else
    echo "   ✗ AWS 配置文件不存在"
    echo "   请先运行: aws configure sso"
    exit 1
fi

# 检查 SSO 登录状态
echo ""
echo "5. 检查 SSO 登录状态..."

# 获取第一个 AdministratorAccess profile
FIRST_PROFILE=$(aws configure list-profiles 2>/dev/null | grep -i "administratoraccess" | head -1 || echo "")

if [ -n "$FIRST_PROFILE" ]; then
    if aws sts get-caller-identity --profile "$FIRST_PROFILE" &>/dev/null; then
        ACCOUNT_ID=$(aws sts get-caller-identity --profile "$FIRST_PROFILE" --query Account --output text)
        echo "   ✓ SSO 已登录 (账户: $ACCOUNT_ID)"
        SSO_LOGGED_IN=true
    else
        echo "   ✗ SSO 未登录或 token 已过期"
        echo ""
        read -p "   是否现在登录? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            aws sso login --profile "$FIRST_PROFILE"
            echo "   ✓ 登录成功"
            SSO_LOGGED_IN=true
        else
            echo "   请稍后手动登录: aws sso login --profile $FIRST_PROFILE"
            SSO_LOGGED_IN=false
        fi
    fi
else
    echo "   ! 未找到 SSO profile"
    SSO_LOGGED_IN=false
fi

# 检查脚本文件
echo ""
echo "6. 检查脚本文件..."
if [ -f "get_waf_config.py" ]; then
    echo "   ✓ get_waf_config.py 存在"
else
    echo "   ✗ get_waf_config.py 不存在"
    exit 1
fi

if [ -f "analyze_waf_config.py" ]; then
    echo "   ✓ analyze_waf_config.py 存在"
else
    echo "   ! analyze_waf_config.py 不存在（可选）"
fi

# 给脚本添加执行权限
chmod +x get_waf_config.py 2>/dev/null || true
chmod +x analyze_waf_config.py 2>/dev/null || true

echo ""
echo "=========================================="
echo "环境检查完成!"
echo "=========================================="
echo ""

if [ "$SSO_LOGGED_IN" = true ]; then
    echo "✓ 你的环境已就绪，可以开始扫描 WAF 配置"
    echo ""
    echo "运行以下命令开始:"
    echo ""
    echo "  # 扫描所有账户（所有 SSO profiles）"
    echo "  python3 get_waf_config.py"
    echo ""
    echo "  # 扫描特定账户"
    echo "  python3 get_waf_config.py -p $FIRST_PROFILE"
    echo ""
    echo "  # 只扫描特定区域"
    echo "  python3 get_waf_config.py -r us-east-1 us-west-2"
    echo ""
    echo "  # 查看所有选项"
    echo "  python3 get_waf_config.py --help"
    echo ""

    read -p "是否现在执行快速扫描（仅 us-east-1）? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        echo "开始快速扫描..."
        python3 get_waf_config.py -r us-east-1 -p "$FIRST_PROFILE"
    fi
else
    echo "⚠ 请先登录 AWS SSO:"
    echo ""
    if [ -n "$FIRST_PROFILE" ]; then
        echo "  aws sso login --profile $FIRST_PROFILE"
    else
        echo "  aws sso login"
    fi
    echo ""
    echo "然后重新运行此脚本或直接运行:"
    echo "  python3 get_waf_config.py"
fi

echo ""
