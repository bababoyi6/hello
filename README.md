# Telegram WEB 代理

用一个 Cloudflare Worker 运行个人 Telegram WEB 代理。部署只需一个 Cloudflare 账号、一个自定义域名和密钥 `p`。请使用支持 **WEB 代理**的 Telegram 客户端。

## 部署与使用

1. 在 Cloudflare Dashboard 创建一个 **Worker**。打开 **编辑代码**，用 [telegram_webproxy.js](./telegram_webproxy.js) 的完整内容替换默认代码并部署。
2. 在 **设置 → 变量和密钥** 添加名为 `p` 的 **Secret**。用密码管理器生成一条独立的随机密码，长度至少 16 字符，保存后部署。
3. 在 **设置 → 域和路由** 添加 **自定义域**。证书生效后，打开 `https://你的域名/admin`，用 `p` 登录。复制生成的 `tg://webproxy` 链接，在 Telegram 中打开并启用。

## 更新与诊断

升级时替换 Worker 中的完整 JS。同域名、同 `p` 的部署可继续使用原代理链接。请把密码和代理链接都当作私密凭据保存。

普通 Telegram 数据中心优先走 TCP，建连失败自动回退到 KWS。媒体连接继续使用 KWS。在 `/admin` 打开 **连接诊断**，可查看当前 Worker 实例的 TCP、KWS、首批转发和缓冲统计。

## 开发

使用 Node.js 24 运行 `npm ci`、`npm test` 和 `npm run test:runtime`。这些命令用于仓库测试。性能结果、协议取舍和验证范围见[源码审计与优化报告](./docs/optimization-audit.md)。

[GPL-3.0 许可证](./LICENSE)
