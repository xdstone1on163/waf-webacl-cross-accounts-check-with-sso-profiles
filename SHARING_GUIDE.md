# 📤 代码分享准备指南

## 🎯 快速开始

在分享此代码之前，运行以下命令：

```bash
# 1. 运行安全检查
./security_check.sh

# 2. 清理敏感文件
rm -f waf_config_*.json
rm -f *.csv
rm -f waf_scan_config.json  # 包含你的真实 profile

# 3. 确认 .gitignore 生效
git status

# 4. 完成！
```

---

## 📋 完整检查清单

### 阶段 1: 清理敏感数据 (5 分钟)

- [ ] 删除所有 `waf_config_*.json` 文件
- [ ] 删除所有 CSV 导出文件
- [ ] 移除或重命名 `waf_scan_config.json`（包含真实 profile）
- [ ] 确保 `waf_scan_config.json.example` 存在
- [ ] 检查代码注释中是否有真实账户信息

### 阶段 2: 验证代码 (3 分钟)

- [ ] 运行 `./security_check.sh` 通过所有检查
- [ ] 确认 `get_waf_config.py` 不包含硬编码的 profile
- [ ] 测试代码能否正常运行（使用测试 profile）
- [ ] 检查 README 示例是否使用占位符

### 阶段 3: Git 准备 (2 分钟)

- [ ] 确认 `.gitignore` 文件存在且配置正确
- [ ] 运行 `git status` 确认没有敏感文件被跟踪
- [ ] 如果使用 Git，检查历史记录是否干净

### 阶段 4: 文档准备 (5 分钟)

- [ ] README 包含清晰的使用说明
- [ ] 添加安全警告和最佳实践
- [ ] 说明如何配置 AWS 权限
- [ ] 包含故障排查指南

---

## 🔧 清理命令

### 方案 A: 手动清理（推荐）
```bash
# 进入项目目录
cd /path/to/waf-config-list-with-sso-profile

# 1. 删除敏感输出文件
rm -f waf_config_*.json
rm -f *.csv

# 2. 备份并删除真实配置
mv waf_scan_config.json waf_scan_config.json.backup  # 备份到当前目录外
# 或者
mv waf_scan_config.json ~/private/

# 3. 确认清理结果
ls -la

# 4. 运行安全检查
./security_check.sh
```

### 方案 B: 自动清理
```bash
# 创建清理脚本
cat > cleanup.sh << 'EOF'
#!/bin/bash
echo "开始清理敏感文件..."

# 备份到用户主目录
BACKUP_DIR=~/waf_backup_$(date +%Y%m%d_%H%M%S)
mkdir -p "$BACKUP_DIR"

# 移动而不是删除（更安全）
if ls waf_config_*.json 1> /dev/null 2>&1; then
    mv waf_config_*.json "$BACKUP_DIR/" 2>/dev/null || true
    echo "✓ WAF 配置文件已移动到 $BACKUP_DIR"
fi

if [ -f waf_scan_config.json ]; then
    mv waf_scan_config.json "$BACKUP_DIR/" 2>/dev/null || true
    echo "✓ 扫描配置已移动到 $BACKUP_DIR"
fi

if ls *.csv 1> /dev/null 2>&1; then
    mv *.csv "$BACKUP_DIR/" 2>/dev/null || true
    echo "✓ CSV 文件已移动到 $BACKUP_DIR"
fi

echo ""
echo "清理完成！备份位于: $BACKUP_DIR"
echo "运行 ./security_check.sh 验证"
EOF

chmod +x cleanup.sh
./cleanup.sh
```

---

## 🌐 不同分享场景的建议

### 场景 1: GitHub 公开仓库

**必须执行**：
```bash
# 1. 彻底清理
rm -f waf_config_*.json *.csv waf_scan_config.json

# 2. 确认 .gitignore
cat .gitignore | grep -E "(waf_config|\.json|\.csv)"

# 3. 检查 Git 历史
git log --all --full-history --source -- "*.json" "*.csv"

# 4. 如果历史中有敏感文件，清理历史
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch 'waf_config_*.json' '*.csv' 'waf_scan_config.json'" \
  --prune-empty --tag-name-filter cat -- --all

# 5. Force push（如果必要）
git push origin --force --all
```

**推荐添加**：
- LICENSE 文件（如 MIT）
- CONTRIBUTING.md
- CODE_OF_CONDUCT.md
- GitHub Actions 用于自动安全扫描

### 场景 2: 公司内部 Git

**必须执行**：
```bash
# 1. 基本清理
rm -f waf_config_*.json *.csv

# 2. 替换真实配置为模板
mv waf_scan_config.json waf_scan_config.json.personal
cp waf_scan_config.json.example waf_scan_config.json.example

# 3. 添加内部文档
# - 说明如何获取 AWS 权限
# - 提供内部联系人信息
# - 团队最佳实践
```

**可选**：
- 保留一些匿名化的账户 ID（如果公司政策允许）
- 添加公司特定的配置说明

### 场景 3: 一对一分享（电子邮件、Slack）

**必须执行**：
```bash
# 1. 清理敏感文件
rm -f waf_config_*.json *.csv waf_scan_config.json

# 2. 创建 ZIP 包
zip -r waf-tool-$(date +%Y%m%d).zip . \
  -x "*.git*" -x "__pycache__/*" -x "*.pyc" \
  -x "waf_config_*.json" -x "*.csv"

# 3. 验证 ZIP 内容
unzip -l waf-tool-$(date +%Y%m%d).zip | grep -E "(json|csv)"
```

**建议包含**：
- 个人使用说明（一页 PDF）
- 快速开始视频（可选）
- 你的联系方式

### 场景 4: 技术博客/文章

**必须执行**：
```bash
# 使用完全匿名的示例数据
# 账户 ID: 123456789012, 987654321098
# Profile: your-aws-profile, prod-account
# 区域: us-east-1, us-west-2
```

**建议**：
- 提供 GitHub Gist 链接而不是完整代码
- 使用代码截图（确保没有敏感信息）
- 添加"此代码仅供教育用途"的声明

---

## 🔐 额外安全措施

### 1. 设置 Git Hooks（防止意外提交）

```bash
# 创建 pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# 防止提交敏感文件

if git diff --cached --name-only | grep -E "waf_config_.*\.json|.*\.csv"; then
    echo "❌ 错误: 尝试提交敏感文件！"
    echo "这些文件包含 AWS 账户信息，不应提交到 Git"
    exit 1
fi

# 检查是否包含真实的账户 ID
if git diff --cached | grep -E "\b[2-9][0-9]{11}\b"; then
    echo "⚠️  警告: 检测到可能的 AWS 账户 ID"
    echo "请确认这不是真实的账户 ID"
    read -p "继续提交？(y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi
EOF

chmod +x .git/hooks/pre-commit
```

### 2. 使用 git-secrets

```bash
# 安装 git-secrets
brew install git-secrets  # macOS
# 或
git clone https://github.com/awslabs/git-secrets.git
cd git-secrets
make install

# 配置
cd /path/to/your/repo
git secrets --install
git secrets --register-aws

# 扫描
git secrets --scan
git secrets --scan-history
```

### 3. 环境变量方式

如果需要频繁使用，考虑使用环境变量：

```bash
# 在 ~/.bashrc 或 ~/.zshrc 中
export WAF_SCAN_PROFILES="profile1,profile2,profile3"
export WAF_SCAN_REGIONS="us-east-1,us-west-2"

# 修改代码读取环境变量
import os
profiles = os.environ.get('WAF_SCAN_PROFILES', '').split(',')
```

---

## ✅ 验证清单

分享前，确认以下所有项目：

**文件清理** ✓
- [ ] 没有 `waf_config_*.json` 文件
- [ ] 没有 CSV 导出文件
- [ ] 没有包含真实 profile 的配置文件
- [ ] `.gitignore` 文件配置正确

**代码检查** ✓
- [ ] 没有硬编码的 AWS 凭证
- [ ] 没有硬编码的真实 profile 名称
- [ ] 没有真实的账户 ID（除文档示例）
- [ ] 代码能够正常运行

**文档检查** ✓
- [ ] README 清晰易懂
- [ ] 包含安全警告
- [ ] 示例使用占位符数据
- [ ] 有 LICENSE 文件（如果需要）

**Git 检查** ✓
- [ ] `git status` 显示干净
- [ ] 历史记录不包含敏感文件
- [ ] `.gitignore` 已生效

**测试** ✓
- [ ] `./security_check.sh` 通过
- [ ] 代码在新环境中可运行
- [ ] 文档说明准确

---

## 🆘 紧急情况处理

### 如果已经推送了敏感信息到 GitHub

**立即执行**：

1. **删除仓库**（如果刚推送不久）
   - 最安全的方式：直接删除整个仓库
   - 重新创建干净的仓库

2. **联系 GitHub 支持**
   ```
   https://support.github.com/contact
   主题: Request to remove sensitive data
   ```

3. **轮换凭证**
   - 如果暴露了 AWS 凭证，立即在 IAM 中禁用
   - 轮换所有相关的访问密钥
   - 检查 CloudTrail 日志

4. **清理历史**（如果必须保留仓库）
   ```bash
   # 使用 BFG Repo-Cleaner（更快）
   java -jar bfg.jar --delete-files "waf_config_*.json" .
   git reflog expire --expire=now --all
   git gc --prune=now --aggressive
   git push --force
   ```

### 监控和警报

设置 AWS 警报监控异常活动：
```bash
# CloudWatch 警报
# 监控意外的 API 调用
# 设置账单警报
```

---

## 📞 获取帮助

- **技术问题**: 查看 `SECURITY_CHECKLIST.md`
- **安全问题**: 运行 `./security_check.sh`
- **AWS 安全**: https://aws.amazon.com/security/
- **Git 安全**: https://docs.github.com/en/code-security

---

## 📝 记录

每次分享前，建议记录：
- [ ] 分享日期
- [ ] 分享给谁
- [ ] 分享方式（GitHub/内部/邮件等）
- [ ] 安全检查是否通过
- [ ] 特殊注意事项

---

**最后提醒**: 当不确定时，选择更保守的方式。宁可过度小心，也不要泄露敏感信息。
