# Telegram WEB 代理源码审计与优化

审计基线为 `hello` 的 `cc6854dac1e368c9ad1b3467bcc7cee276c893c7`。验收以 `p`、自定义域名和单个 JS 为部署条件，保留 `/admin`、原代理链接格式、逐流 WebSocket 和官方 Telegram KWS 上游。

## 源码对照

| 项目 | 审读范围与证据 | 对本项目的取舍 |
| --- | --- | --- |
| `hello` | `route`、`runBridge` 和 `Lane` 贯穿后台、载体鉴权、客户端额度、上游选择、CTR 转码和异常清理。上线基线只含 Worker、说明和许可证。 | 保留现有 KWS 传输和票据协议，优先修复可以独立重现的丢尾包、缓冲记账和连接诊断问题。 |
| `cftgwebproxy` · `192e675` | `mkWire` 用 KWS `binary` 子协议，主备顺序拨号，上传切为完整传输包，下行解密后重加密。`mkPkt` 会复制已积累的尾段。解码队列有额度，原生 KWS 接收后的待处理队列也需单独考虑。其余源码包含中继的请求头/CSP 改写及发出外部请求的 DNS Worker。该提交没有独立自动化测试。 [转发 Worker](https://github.com/xinyitang3/cftgwebproxy/blob/192e675011f6ea06b97ae7da88213a48b7909748/telegram_webproxy.js#L43-L85) · [中继](https://github.com/xinyitang3/cftgwebproxy/blob/192e675011f6ea06b97ae7da88213a48b7909748/webproxy-relay.js) · [DNS](https://github.com/xinyitang3/cftgwebproxy/blob/192e675011f6ea06b97ae7da88213a48b7909748/domain-dns.js) | 用其 KWS 路径交叉核对二进制子协议、头部和封包边界。保留 `hello` 的额度和分层预算，避免分片每次都合并。生产部署仍是已有单 Worker 链路。 |
| `ProxyGosha` · `376b329` | `Stream.init()` 走 TCP，使用总拨号期限、单次期限、并发额度和端点冷却。`Stream.pump()` 由下行额度驱动 TCP 读取，直接送下行密文，`kill()` 释放定时器、读写锁和流。另有载体心跳、HTTP 轮询重试和缓存、HMAC 票据、测速档位、主动探测与有界日志。该提交没有独立自动化测试。 [TCP 流](https://github.com/amirmarandidev/ProxyGosha/blob/376b3295594af154bd884d4bae4a2b1ebea1c422/worker.js#L2876-L3290) · [测速档位](https://github.com/amirmarandidev/ProxyGosha/blob/376b3295594af154bd884d4bae4a2b1ebea1c422/worker.js#L220-L252) · [鉴权及管理](https://github.com/amirmarandidev/ProxyGosha/blob/376b3295594af154bd884d4bae4a2b1ebea1c422/worker.js#L2427-L2622) | 借鉴按传输阶段统计、等待期限和结束清理。保留独立 Lane 的失败隔离和现有可诊断的固定缓冲上限。 |
| `TWP` · `e94f459` | `generateDcHandshake()` 复用客户端下行密钥和 IV，`connectToDatacenter()` 顺序拨号直连 TCP，`pumpDownlink()` 受窗口控制直接发送密文。载体集中复用多个流，具备票据、帧校验及超时。测试包括 TCP 上的下行不变量、计数器进位、帧、票据、主备和端到端模拟。 [DC 握手](https://github.com/Qorvhex/TWP/blob/e94f45949e2017462724f12582823f5c1c6996ad/worker.js#L426-L516) · [下行](https://github.com/Qorvhex/TWP/blob/e94f45949e2017462724f12582823f5c1c6996ad/worker.js#L612-L689) · [测试](https://github.com/Qorvhex/TWP/blob/e94f45949e2017462724f12582823f5c1c6996ad/test/worker.test.mjs) | 用独立密钥、独立计数器、任意分片和模拟上游验证 KWS 链路，增加本地 workerd 验证。保持现有载体格式。 |

三个审读版本的许可证均为 MIT。本次从参考实现借鉴设计和测试思路，改动基于本项目代码独立实现。仓库继续按 [GPL-3.0](../LICENSE) 分发。

## CTR 与 KWS

Obfuscated2 的 64 字节客户端头将双向材料从中间 48 字节按正反方向分别取出。对代理链路，相应密钥材料与代理密钥一起做 SHA-256。客户端上传流在处理头之后从偏移 64 继续，下行从偏移 0 开始。当前 Worker 向 KWS 建立一套独立握手，使用随机头，分别得到两套上下行 CTR 状态。上传以完整 MTProto transport 包写入 KWS WebSocket，下行按字节流处理，分片只推进实际经过的 CTR 字节。 [Telegram transport obfuscation](https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation) · [Telegram transport](https://core.telegram.org/mtproto/transports) · [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final)

TWP 和 ProxyGosha 直通方案把派生后的客户端下行密钥和 IV 逆向写入上游头部的可见字节，通过 TCP 上游生成客户端可直接消费的下行密文。这个等式要求两侧从同一个计数器位置处理完全相同的字节序列，也要求同一密钥和计数器序列只服务同一个逻辑密文字节流。向另一个端点发送相同下行材料、重放头部，或把相同的 CTR 序列用于不同明文，都可能造成密钥流复用。上游 TLS 会保护链路传输，握手字段仍向上游终止点披露该客户端的下行密钥材料。

KWS 需另外证明 `binary` 子协议、各 transport mode、媒体 DC 和断线行为满足这些不变量。TCP 测试只能证明其所构造的上游语义，现有公开协议和本地模拟无法验证生产 KWS 的全部行为。此版本继续使用两段独立 CTR。`createCTR()` 只在前一段新生成的私有缓冲正好符合后一段的偏移和长度时复用它的填充空间，清零视图外的前缀和尾部。两段加密的调用次数、计数器推进和密钥派生全部保留。独立 Node AES 参考值和 workerd 上的分片传输校验均通过。 [Telegram Desktop 载体协议](https://github.com/telegramdesktop/tproxy-server/blob/master/PROTOCOL.md)

## 已实施改动

| 优先级 | 问题与位置 | 实现和验证 |
| --- | --- | --- |
| 高 | `Lane.enqueueDown`、`pumpDown` 和上游关闭 | KWS 以 `1000` 关闭时，在仍有下行数据的情况下，按额度发送已接收的数据，再关闭 Lane。异常断开、撤销和过期即时收尾。尾包等待有期限，关闭后停止接收新上传数据。测试覆盖尾包顺序、阻塞期限、并行 Lane 继续工作和预算归零。 |
| 高 | `writeNative`、`reconcileNative`、`drain`、Bridge 发送队列 | 检查读数为非负安全整数，并处理读取抛错。原生读数从连接开始即不可用时使用应用层额度和上限。已经记账的原生队列失去读数时关闭该 Lane。发送有进展时及时继续，无进展时降低轮询频率。测试覆盖缺失值、`NaN`、慢客户端、时间上限和定时器取消。 |
| 高 | `scheduleNativeCheck` 与半开连接 | 只要原生发送队列仍有已记账数据，就分别记录客户端和上游的进展。即使队列小于拥塞阈值，一侧持续 30 秒无进展也会释放 Lane 和缓冲。另一侧有进展不会掩盖该停滞。空队列停止轮询，正常空闲连接保持在线。 |
| 高 | `PacketAssembly.add` | 原先收到声明最大长度的四字节头即预分配约 8 MiB。现在按已收字节增长，四字节头占用 64 KiB 分配；扩容期间两个缓冲都计账。正常的大分片上传会产生额外的增长复制，见实测。每条 KWS 上传消息仍是完整的 transport 包。 |
| 高 | `routePortal`、`configuration` | 提前拒绝超限的 `Content-Length`，上限为 1024 字节。拒绝不合理的 Cookie 有效期，异步验签后重新检查过期。保持密码、代理密钥和票据编码兼容。 |
| 中 | `createCTR`、`pumpDown` | 减少非对齐下载中的 JS 中间复制，保留 WebCrypto AES-CTR、块内尾部和 128 位进位检查。同步推入 KWS 事件回调，使 workerd 的事件处理无需接收一个未使用的 Promise。 |
| 中 | `connectKWS`、`UpstreamRouter`、`portalDiagnostics` | 每个 DC 的普通及媒体线路记录成功率、P95、备用尝试、取消和有限错误类别，区分 Bridge 签发、载体升级、上游握手和实际转发。记录应用层缓冲峰值及关闭原因。所有数据来自已有连接，手动 HTTPS 计时按钮仍按用户操作触发。 |

生产路径继续走固定的官方 KWS 主备域名，拒绝跟随重定向。默认单次拨号 3 秒，主路迟滞 900 毫秒后可开启备用，最多两个候选和每实例八个并发备用竞速。较晚返回的 Upgrade 会释放，备用路径独立冷却。Bridge 保留快速票据，并在需要续期或退化到旧载体握手时，对短暂的 HTTP 故障按总期限重试，尊重可用的 `Retry-After`。网络切换由客户端按 Lane 恢复，Worker 不重放业务数据。连接空闲时不加主动心跳；等待头部、部分上传包、发送额度、回压和父会话到期均有边界。TCP 代码只用于现有兼容测试和本地对照，默认 Worker 入口使用 KWS。

`WINDOW` 为 4 MiB，`DOWN_FRAME` 为 64 KiB，`CRYPT_CHUNK` 为 512 KiB，`SOCKET_BUFFER` 目标为 2 MiB，`PACK` 和 `BULK_PACK` 分别为 32 KiB 和 256 KiB。合包只消化已排队数据，保留小消息快路径。应用预算按 Lane 32 MiB、父会话 36 MiB、实例 40 MiB 分层记账。可读的原生排队数据也入账。缺失原生读数时，应用额度能约束自身数据，无法量到已交给 `send()` 的运行时缓冲。原生内存、GC 和其他对象也由运行时计费。固定上限和基于发送进度的轮询已经覆盖本地慢客户端场景；扩大窗口、自动测速档位和正常流量额外控制请求没有采用。

## 安全边界与免费额度

- 单密钥部署用绑定域名的 PBKDF2-SHA-256（16,000 次）派生原始材料，再用 HKDF 域分隔产生 128 位代理密钥和载体签名密钥。Bridge capability 为带域名上下文的 HMAC，载体票据另绑定用途、域名、有效期和会话 ID。Fast/Bootstrap 票据为 90/120 秒，常规票据可续到 5 分钟，续期授权最长 12 小时。代理链接或 Bridge capability 泄露后，弱 `p` 可被离线猜测。修改默认派生会更换现有链接，因此保留既有参数，部署文档要求独立随机 `p`。
- 后台 Cookie 使用 `Secure`、`HttpOnly`、`SameSite=Strict` 和 `/admin` 路径，登录与退出检查 Origin。载体允许缺少 Origin 的兼容请求，带 Origin 时要求匹配，并继续验证凭据。JS 使用 nonce CSP、`no-store`、`no-referrer`，Bridge 会在加载后清除浏览器地址查询参数。原有客户端首个请求必须携带查询参数 `bridge`，它仍可能进入平台访问日志或调用日志；启用日志时须保护查询字符串及会话相关头部。诊断只含固定分类和聚合计数。 [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/)
- 客户端帧校验类型、流 ID、长度、额度和会话期限。登录限流为同实例每域名/IP 每分钟 8 次、总计 120 次，Lane 为每父会话 64、每实例 128。已用 Lane ID 和 DELETE 撤销记录属于实例内存，每组最多 4,096 个 ID、每实例最多 16,384 个。票据跨实例验签，但实例之间不共享撤销、去重和限流记录。现有链接可签发新的 Bridge 会话；密码和链接应视为凭据。
- 按审计日的 Workers Free 文档，免费账户每日 100,000 个传入请求，CPU 上限 10 ms，内存上限 128 MB（每 isolate），每次调用 50 个子请求、最多 6 个同时等待响应头的外连。每次初始 WebSocket Upgrade 计入请求，后续消息不各算一条请求。正常首连走一次 Bridge、每 Lane 一次 Upgrade 和一次 KWS 拨号。边缘运行时的 CPU、原生缓冲、重启以及 WebSocket 生命周期仍受平台管理。 [Workers Limits](https://developers.cloudflare.com/workers/platform/limits/) · [Workers Pricing](https://developers.cloudflare.com/workers/platform/pricing/) · [Workers WebSocket API](https://developers.cloudflare.com/workers/runtime-apis/websockets/)

## 验证与复现

基线通过 81 项 Node 测试和 8 项本地 workerd 测试。改版通过 99 项 Node 测试和 10 项本地 workerd 测试。用例覆盖标准 AES-CTR 测试向量、任意分片和计数器进位，载体与 MTProto 帧、损坏输入、鉴权和原代理密钥向量，双向传输、最大包、并行 Lane、回压与预算、主备、迟到响应、超时、过期以及清理。workerd 验证包含只提供 `p` 的打包文件、模拟 KWS 与原生 WebSocket、客户端或上游先关闭，以及原生 TCP 回环连接上的分片双向传输和 EOF。CI 使用固定依赖，并验证两条传输路径的批量数据完整性。

```sh
npm ci
npm test
npm run test:runtime
node --expose-gc benchmarks/transport.mjs --sizes --against=cc6854dac1e368c9ad1b3467bcc7cee276c893c7
node --expose-gc benchmarks/transport.mjs --quick --sizes --verify --copy-stats --against=cc6854dac1e368c9ad1b3467bcc7cee276c893c7
node benchmarks/startup.mjs --against=cc6854dac1e368c9ad1b3467bcc7cee276c893c7
```

### 对照结果

本机 Windows、Node.js 24.16.0，采用模拟 KWS 和载体 WebSocket、真实 WebCrypto。传输计时每组 7 次交错执行，报告运行中位数和批次 P95。显式复制单独运行 3 次，统计 Worker 中 `Uint8Array.set` 执行次数和字节数，不含 `slice`、底层 WebCrypto、浏览器与运行时复制；此轮也做 SHA-256 完整性校验。采样 `ArrayBuffer` 峰值受 GC、2 ms 采样与短场景影响；CPU 是 Node 进程采样，在该 Windows 环境常以约 16 ms 为单位，不能用来验证 Workers 的 10 ms 账单限额。

| 场景 | 吞吐 MiB/s | 批次 P95 ms | 进程 CPU ms | 记账峰值 MiB | WebCrypto 加密次数 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 交互小包 | 1.342 → 1.321 | 0.131 → 0.128 | 0 → 0 | 0.001 → 0.001 | 880 → 880 |
| 交互与媒体 | 307.899 → 312.663 | 2.057 → 1.963 | 16 → 15 | 3.271 → 3.149 | 864 → 864 |
| 持续下载 | 840.513 → 878.238 | 1.500 → 1.611 | 0 → 0 | 1.502 → 1.502 | 256 → 256 |
| 1 MiB 包下载 | 1229.448 → 1228.808 | 2.566 → 2.443 | 31 → 16 | 4.001 → 4.001 | 256 → 256 |
| 非对齐媒体下载 | 704.135 → 844.599 | 2.674 → 1.521 | 0 → 0 | 1.876 → 1.626 | 120 → 120 |
| 分片媒体上传 | 451.076 → 426.480 | 6.320 → 6.426 | 16 → 31 | 3.553 → 3.553 | 624 → 624 |
| 慢客户端持续下载 | 7.963 → 7.958 | 125.259 → 125.123 | 0 → 0 | 3.378 → 3.378 | 128 → 128 |

每格为旧版 → 改版。非对齐媒体下载的显式复制为 **732 次、47,189,544 字节 → 672 次、34,606,920 字节**。分片媒体上传为 **3,070 次、97,050,312 字节 → 3,166 次、118,283,976 字节**，这是避免声明长度触发过早预分配的代价。同批交互小包及持续下载的复制完全相同。普通 1 MiB 下载的 `ArrayBuffer` 采样峰值为 24.509 → 24.009 MiB，非对齐媒体为 30.505 → 18.630 MiB。短批次可能错过进程峰值，以记账峰值和单独的复制计数为证据更稳妥。计时轮有快有慢，结果仅代表这些本地负载。

| 建连场景（每版 40 轮） | 模拟 KWS 握手 P95 ms | 首次转发 P95 ms | 成功次数 |
| --- | ---: | ---: | ---: |
| 新实例 | 6.767 → 6.754 | 8.291 → 7.705 | 40 → 40 |
| 已预热实例 | 2.109 → 2.274 | 2.515 → 2.770 | 40 → 40 |
| 模拟主路立即失败 | 6.870 → 7.079 | 7.698 → 7.976 | 40 → 40 |

建连计时从 Bridge 请求开始。两版正常快速路径的额外 session POST 都是 0，成功 KWS 拨号为 1 次，主路人为失败时是 2 次。新实例同时签发 8 个 Bridge 的 P95 为 4.809 → 6.262 ms，均只调用一次 PBKDF2；进程 CPU P95 均为 16 ms。超时、竞速取消和慢队列恢复另用可控时钟验证，表格不包含真实线路延迟。

### TCP 与 KWS 专项对照

这两条上游都保留独立的传输密钥。TCP 开销主要来自 `ReadableStream` 的 BYOB 读、`WritableStream` 写和调度，KWS 则由完整 WebSocket 消息驱动及合包。TCP 链路只使用当前已核对的普通 DC 引导地址。生产媒体路由还需区分数据中心的 `media_only`、端口和密钥等参数。TCP 直连的上游没有外层 TLS，KWS 则由 TLS 提供外层链路保护。 [Cloudflare TCP sockets](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/) · [Telegram transport](https://core.telegram.org/mtproto/transports) · [Telegram DC 配置](https://core.telegram.org/api/datacenter)

本地整组对照使用 `a6310c1` 的两条路径、相同的 Node 模拟载体和 7 轮交错计时。KWS 和 TCP 中位数如下，所谓媒体大小指负载规模，TCP 测试使用普通 DC。运行 `node --expose-gc benchmarks/transport.mjs --sizes --tcp` 可复现。

| 模拟负载 | KWS / TCP 吞吐（MiB/s） | KWS / TCP 批次 P95（ms） |
| --- | ---: | ---: |
| 交互小包 | 1.38 / 0.91 | 0.134 / 0.190 |
| 交互与媒体大小混合包 | 311.29 / 217.18 | 2.153 / 2.803 |
| 16 KiB 下载 | 248.37 / 352.05 | 0.76 / 0.51 |
| 持续下载 | 841.74 / 741.93 | 1.76 / 2.99 |
| 1 MiB 包下载 | 1,191.12 / 776.60 | 2.96 / 4.38 |
| 慢客户端持续下载 | 7.97 / 7.99 | 125.19 / 124.90 |

补测用随机 nonce 发出标准未认证握手，并只接受 nonce 匹配的 `resPQ`。本机公网两轮从开始连接到收到响应，普通 TCP 为 907–2,287 ms、普通 KWS 为 1,942–3,446 ms、媒体 KWS 为 1,859–4,255 ms，三类各 6 次均成功。首轮试测另有两个 KWS 响应超出 3 秒，正式对照统一使用 6 秒。匿名 Cloudflare Playground 中，探针同样验证响应，预览请求的 `colo` 为 **ORD（芝加哥）**。每格为拨号开始至经过校验的响应时间。

| ORD 样本 | 普通 TCP（ms） | 普通 KWS（ms） | 媒体 KWS（ms） |
| --- | ---: | ---: | ---: |
| DC 1 | 72 | 189 | 208 |
| DC 2，第 1 次 | 291 | 921 | 1,105 |
| DC 2，第 2 次 | 285 | 740 | 829 |
| DC 5 | 443 | 1,270 | 1,297 |

**生产继续使用 KWS。** TCP 在实测路径上的普通 DC 初始响应更快，KWS 在多数本地传输负载中有更好的吞吐和批次 P95。ORD 的四个样本没有覆盖亚洲边缘、长期会话或登录后媒体传输，目前也缺少 TCP 媒体和主备路由同等覆盖。TCP 实验留在自动化测试与基准里。生产入口不加额外拨号、定时探测或传输切换。 [Telegram 初始握手](https://core.telegram.org/mtproto/samples-auth_key) · [Cloudflare Workers Playground](https://developers.cloudflare.com/workers/playground/)

### 实机验收范围

本机及匿名 Playground 测试未访问用户的 Cloudflare 账户和域名。Playground 只运行无凭据的合成握手。生产 Worker 的边缘 CPU、内存、亚洲入口与实际回源线路、长期后台在线、Wi-Fi/移动网络切换后的重建，以及 Windows、iOS、Android 的真实 Telegram 客户端，均未验证。协议向量和 Bridge MessagePort 测试覆盖可复现的客户端接口，生产网络质量和客户端完整行为仍须以真实会话为准。
