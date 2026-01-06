# 🔒 分享前安全检查清单

在将此代码分享给他人或提交到 Git 仓库之前，请务必完成以下检查：

## ✅ 必须检查的项目

### 1. 删除所有包含真实数据的 JSON 文件
```bash
# 删除所有 WAF 配置输出文件
rm -f waf_config_*.json

# 或者移动到安全位置
mkdir -p ~/private_waf_data
mv waf_config_*.json ~/private_waf_data/
```

**这些文件可能包含**：
- AWS 账户 ID
- 资源 ARN（包含账户 ID、区域、资源 ID）
- Web ACL 配置详情
- 关联的 AWS 资源信息

---

### 2. 检查并移除硬编码的 AWS Profile 名称
```bash
# 搜索可能的 profile 名称
grep -r "AdministratorAccess-" .
grep -r "AWSReservedSSO" .
```

**需要检查的文件**：
- ✅ `get_waf_config.py` - 已修改为强制要求用户指定 profile
- ⚠️ `waf_scan_config.json` - 包含你的实际 profile，应删除或重命名
- ⚠️ `README_WAF.md` - 示例中的账户 ID 可以保留（作为示例）

---

### 3. 搜索并移除账户 ID
```bash
# 搜索 12 位数字（AWS 账户 ID 格式）
grep -rE "\b[0-9]{12}\b" . --exclude-dir=.git
```

**可以保留的位置**：
- 文档示例中的虚构账户 ID（如 `123456789012`）
- 已经是公开的示例账户 ID

**必须移除的位置**：
- 任何真实的配置文件
- 代码注释中的真实账户 ID
- 测试数据中的真实账户 ID

---

### 4. 创建并确认 .gitignore 文件
```bash
# 确认 .gitignore 存在并包含以下内容
cat .gitignore
```

**必须包含**：
```gitignore
waf_config_*.json
*.json
!waf_scan_config.json.example
*.csv
waf_*.csv
.env
.env.local
config.local.json
```

---

### 5. 检查其他可能的敏感信息
```bash
# 搜索常见的敏感信息模式
grep -riE "(access.*key|secret|password|token|credential)" . --exclude-dir=.git
```

---

## 📋 可选但推荐的项目

### 6. 清理 Git 历史（如果已经提交过敏感信息）
```bash
# 警告：这会重写 Git 历史！
# 从所有历史记录中移除敏感文件
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch waf_config_*.json" \
  --prune-empty --tag-name-filter cat -- --all

# 或使用 BFG Repo-Cleaner（推荐）
# bfg --delete-files waf_config_*.json
```

---

### 7. 添加 LICENSE 文件
```bash
# 选择合适的开源许可证，例如 MIT
```

---

### 8. 更新 README 添加安全提醒
确保 README 中包含：
- ⚠️ 不要将输出的 JSON 文件提交到版本控制
- ⚠️ 不要在代码中硬编码 AWS 凭证或 profile 名称
- ⚠️ 使用最小权限原则配置 IAM 权限

---

## 🎯 快速检查命令

运行以下命令进行快速检查：

```bash
#!/bin/bash
echo "🔍 开始安全检查..."

# 1. 检查 JSON 配置文件
if ls waf_config_*.json 1> /dev/null 2>&1; then
    echo "❌ 发现 WAF 配置文件！请删除或移动："
    ls -lh waf_config_*.json
else
    echo "✅ 未发现 WAF 配置文件"
fi

# 2. 检查硬编码的 profile
if grep -r "AdministratorAccess-[0-9]" . --exclude="SECURITY_CHECKLIST.md" --exclude-dir=.git; then
    echo "❌ 发现硬编码的 AWS profile 名称"
else
    echo "✅ 未发现硬编码的 profile"
fi

# 3. 检查 .gitignore
if [ -f .gitignore ]; then
    echo "✅ .gitignore 文件存在"
else
    echo "❌ 缺少 .gitignore 文件"
fi

# 4. 检查真实账户 ID（排除示例）
if grep -rE "\b[2-9][0-9]{11}\b" . --exclude="SECURITY_CHECKLIST.md" --exclude-dir=.git | grep -v "123456789012"; then
    echo "⚠️  发现可能的真实账户 ID，请确认"
else
    echo "✅ 未发现明显的真实账户 ID"
fi

echo ""
echo "🎉 安全检查完成！"
```

保存为 `security_check.sh` 并运行：
```bash
chmod +x security_check.sh
./security_check.sh
```

---

## 📚 额外建议

### 对于公开分享（GitHub、GitLab 等）
1. ✅ 使用 .gitignore 防止意外提交
2. ✅ 在 README 中添加明确的安全警告
3. ✅ 提供配置文件模板而不是真实配置
4. ✅ 考虑添加 GitHub Actions 扫描敏感信息
5. ✅ 使用 `git-secrets` 或 `truffleHog` 扫描敏感信息

### 对于内部分享（公司内部）
1. ✅ 确认公司的代码分享政策
2. ✅ 移除所有账户标识符（即使是内部账户）
3. ✅ 考虑使用内部 Git 服务器而不是公共平台
4. ✅ 添加内部文档说明如何配置

### 对于商业用途
1. ✅ 添加适当的许可证
2. ✅ 添加免责声明
3. ✅ 考虑代码审计
4. ✅ 提供技术支持文档

---

## ⚠️ 如果不小心暴露了敏感信息

如果你已经将包含敏感信息的代码推送到公共仓库：

1. **立即行动**：
   - 轮换所有可能暴露的凭证
   - 联系 GitHub 支持删除敏感信息
   - 通知安全团队

2. **清理仓库**：
   - 使用 `git filter-branch` 或 BFG 清理历史
   - Force push 到远程仓库
   - 通知所有贡献者重新克隆仓库

3. **预防措施**：
   - 启用 AWS CloudTrail 监控异常活动
   - 设置 AWS 账户警报
   - 审查 IAM 权限和访问日志

---

## 📞 需要帮助？

- AWS 安全最佳实践：https://aws.amazon.com/security/
- GitHub 安全指南：https://docs.github.com/en/code-security
- Git Secrets 工具：https://github.com/awslabs/git-secrets
