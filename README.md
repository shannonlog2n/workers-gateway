# Cloudflare 网关管理系统

基于 Cloudflare Workers 构建的轻量级网关系统，实现简单的路由管理。

## 功能特性

### 核心功能
- **路由管理**
  - 支持两种路由类型（精准匹配）：重定向到特定url / 返回自定义内容（html或者plain text）
  - 路径匹配规则管理
  - 规则启用/禁用状态控制
- **安全认证**
  - 管理后台密码保护
  - Cloudflare Turnstile 人机验证
  - HMAC 签名会话管理
- **安全防护**
  - CSRF 双重验证（Cookie + Header/Body）
  - 严格 CSP 策略
  - XSS/点击劫持防护头
  - 默认页面和404页面伪装为Nginx样式

## 部署要求

### 必需环境变量
```env
TURNSTILE_SITE_KEY=your_site_key     # Turnstile 站点密钥
TURNSTILE_SECRET_KEY=your_secret_key # Turnstile 验证密钥
ADMIN_PASSWORD=your_strong_password # 管理密码
HMAC_KEY=your_hmac_secret           # 建议32位以上随机字符串
```
### KV命名空间
```env
[binding]
name = "GATEWAY"  # 必须使用此名称
```

## 部署流程
1. 创建KV空间：创建名为 GATEWAY 的 KV 命名空间
2. 创建workers：将上面_workers.js内代码复制到workers中
3. 设置环境变量，将上面创建的KV空间绑定的到workers上
4. 为workers绑定自己的域名，因为workers.dev域名已经被大陆封锁
5. 访问```你绑定的域名/admin```进入管理后台

## 使用须知
1. 因为cloudflare KV键值限制 2MB 大小，所以上传的自定义内容不能超过 2MB。
2. ⚠ 没有做缓存机制，所以不宜公开使用
3. 适合用来放一些自己的小脚本或者是配置文件什么的
