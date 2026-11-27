# Telegram WEB 代理

一个运行在 Cloudflare Workers 上的个人 Telegram WEB 代理。使用支持 **WEB 代理**的 Telegram 客户端即可连接。

## 部署

1. 在 Cloudflare 的 **Workers 和 Pages** 创建一个 Worker。打开 **编辑代码**，将默认代码全部替换为 [telegram_webproxy.js](./telegram_webproxy.js) 的内容，然后部署。
2. 在 Worker 的 **设置 → 变量和密钥** 添加名为 `p` 的 **Secret**，使用至少 16 个字符的独立密码，然后保存部署。
3. 在 **设置 → 域和路由** 添加自定义域，等待 HTTPS 证书生效。

## 使用

打开 `https://你的域名/admin`，用 `p` 登录。复制生成的 `tg://webproxy` 链接，在 Telegram 中打开并启用代理。

[GPL-3.0 许可证](./LICENSE)
