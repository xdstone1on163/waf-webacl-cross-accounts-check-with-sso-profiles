#!/bin/bash
# WAF 配置工具 - 安全检查脚本
# 在分享代码前运行此脚本，确保没有敏感信息泄露

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

ISSUES_FOUND=0

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}🔍 WAF 工具安全检查${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# 1. 检查 WAF 配置输出文件
echo -e "${BLUE}[1/7] 检查 WAF 配置输出文件...${NC}"
if ls waf_config_*.json 1> /dev/null 2>&1; then
    echo -e "${RED}❌ 发现 WAF 配置文件（包含敏感数据）：${NC}"
    ls -lh waf_config_*.json
    echo -e "${YELLOW}   建议：rm -f waf_config_*.json${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "${GREEN}✅ 未发现 WAF 配置输出文件${NC}"
fi
echo ""

# 2. 检查其他 JSON 文件（排除示例）
echo -e "${BLUE}[2/7] 检查其他潜在的配置文件...${NC}"
if ls *.json 2>/dev/null | grep -v "\.example$" | grep -v "package.json" | grep -v "package-lock.json" > /dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  发现其他 JSON 文件，请确认是否包含敏感信息：${NC}"
    ls -lh *.json 2>/dev/null | grep -v "\.example$" | grep -v "package.json" | grep -v "package-lock.json" || true
    echo -e "${YELLOW}   如果包含真实配置，请移除或添加到 .gitignore${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "${GREEN}✅ 未发现其他配置文件${NC}"
fi
echo ""

# 3. 检查硬编码的 AWS Profile
echo -e "${BLUE}[3/7] 检查硬编码的 AWS profile 名称...${NC}"
if grep -r "AdministratorAccess-[0-9]" . \
    --exclude="SECURITY_CHECKLIST.md" \
    --exclude="security_check.sh" \
    --exclude-dir=.git \
    --exclude-dir=__pycache__ 2>/dev/null | grep -v "示例\|example\|Example\|README"; then
    echo -e "${RED}❌ 发现硬编码的 AWS profile 名称${NC}"
    echo -e "${YELLOW}   请将其替换为占位符或从配置文件读取${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "${GREEN}✅ 未发现硬编码的 profile（排除文档示例）${NC}"
fi
echo ""

# 4. 检查 AWS 账户 ID
echo -e "${BLUE}[4/7] 检查潜在的真实 AWS 账户 ID...${NC}"
ACCOUNT_IDS=$(grep -rE "\b[2-9][0-9]{11}\b" . \
    --exclude="SECURITY_CHECKLIST.md" \
    --exclude="security_check.sh" \
    --exclude-dir=.git \
    --exclude-dir=__pycache__ 2>/dev/null | \
    grep -v "123456789012\|111111111111\|999999999999" | \
    grep -v "示例\|example\|Example" || true)

if [ -n "$ACCOUNT_IDS" ]; then
    echo -e "${YELLOW}⚠️  发现可能的真实账户 ID（请人工确认）：${NC}"
    echo "$ACCOUNT_IDS" | head -5
    echo -e "${YELLOW}   请确认这些是否为真实账户 ID${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "${GREEN}✅ 未发现明显的真实账户 ID${NC}"
fi
echo ""

# 5. 检查 .gitignore
echo -e "${BLUE}[5/7] 检查 .gitignore 文件...${NC}"
if [ ! -f .gitignore ]; then
    echo -e "${RED}❌ 缺少 .gitignore 文件${NC}"
    echo -e "${YELLOW}   已创建 .gitignore 模板${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    if grep -q "waf_config_\*.json" .gitignore && \
       grep -q "\*.json" .gitignore; then
        echo -e "${GREEN}✅ .gitignore 配置正确${NC}"
    else
        echo -e "${YELLOW}⚠️  .gitignore 可能不完整${NC}"
        echo -e "${YELLOW}   请确保包含: waf_config_*.json 和 *.json${NC}"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
fi
echo ""

# 6. 检查可能的凭证泄露
echo -e "${BLUE}[6/7] 检查可能的凭证信息...${NC}"
CREDS=$(grep -riE "(aws_access_key_id|aws_secret_access_key|AKIA[0-9A-Z]{16})" . \
    --exclude="SECURITY_CHECKLIST.md" \
    --exclude="security_check.sh" \
    --exclude="README*.md" \
    --exclude-dir=.git \
    --exclude-dir=__pycache__ 2>/dev/null | \
    grep -v "YOUR_ACCESS_KEY\|example\|示例" || true)

if [ -n "$CREDS" ]; then
    echo -e "${RED}❌ 发现可能的 AWS 凭证！${NC}"
    echo "$CREDS"
    echo -e "${YELLOW}   立即移除这些凭证！${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "${GREEN}✅ 未发现 AWS 凭证${NC}"
fi
echo ""

# 7. 检查 CSV 导出文件
echo -e "${BLUE}[7/7] 检查 CSV 导出文件...${NC}"
if ls *.csv 1> /dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  发现 CSV 文件（可能包含敏感数据）：${NC}"
    ls -lh *.csv
    echo -e "${YELLOW}   建议：rm -f *.csv 或移动到私有目录${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "${GREEN}✅ 未发现 CSV 文件${NC}"
fi
echo ""

# 总结
echo -e "${BLUE}======================================${NC}"
if [ $ISSUES_FOUND -eq 0 ]; then
    echo -e "${GREEN}🎉 安全检查通过！${NC}"
    echo -e "${GREEN}未发现明显的安全问题${NC}"
    echo ""
    echo -e "${BLUE}建议的后续步骤：${NC}"
    echo "1. 人工审查代码，确认没有遗漏"
    echo "2. 测试 .gitignore 是否生效: git status"
    echo "3. 如有需要，清理 Git 历史记录"
    exit 0
else
    echo -e "${YELLOW}⚠️  发现 ${ISSUES_FOUND} 个潜在问题${NC}"
    echo -e "${YELLOW}请在分享代码前解决这些问题${NC}"
    echo ""
    echo -e "${BLUE}快速修复命令：${NC}"
    echo "# 删除所有敏感文件"
    echo "rm -f waf_config_*.json *.csv"
    echo ""
    echo "# 检查 Git 暂存区"
    echo "git status"
    echo ""
    echo "# 如果已提交，清理历史（谨慎使用！）"
    echo "# git filter-branch --force --index-filter \\"
    echo "#   'git rm --cached --ignore-unmatch waf_config_*.json' \\"
    echo "#   --prune-empty --tag-name-filter cat -- --all"
    exit 1
fi
