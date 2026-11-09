# ddns-rust

用 Rust 构建的 **排障优先 DDNS**。当前 `0.2.0` 支持腾讯云 DNSPod API 3.0、Cloudflare、阿里云 DNS、DNSPod 传统 API、Porkbun、deSEC、DNS.LA、GoDaddy、Vercel、NS1、Name.com、雨云、ClouDNS、dynv6、Spaceship、Gcore、NameSilo、HiPM DNS Manager（仅 Aliyun 映射）、华为云 DNS、百度云 BCD、腾讯云 EdgeOne（原生 TEODNS）和火山引擎 TrafficRoute 和 Namecheap（窄范围 BasicDNS），并提供显式未验证的 JSON POST 回调能力、单二进制、中英双语 Web 管理和英文 JSON 日志。

> 正按上游 29 种服务商分批接入，完整进度与限制见 [服务商清单](<PROVIDERS.md>)。尚未实现的服务商不会出现在可用选择器中，也不会回退到其他服务商。暂不支持 ddns-go 配置直接导入、任意 GET/模板回调或多用户管理。支持 `-s install` 安装并后台启动、`-s uninstall` 停止并卸载 Windows / Linux（systemd）/ macOS 系统服务，见[服务安装说明](<docs/services.md>)。没有真实云账号的端到端验证不应被理解为已完成线上验收。

## 为什么重新做

- 所有腾讯云响应统一检查 `Response.Error`，包括 **HTTP 200 中的业务错误**。
- 错误包含 `stage / code / message / hint / request_id / http_status / retryable`，不再只给一句“查询域名信息发生异常”。
- 每次执行有 `run_id`，每条记录独立失败，不阻止后续记录。
- Web 页面可即时切换 `trace / debug / info / warn / error`，无需重启，并写回配置。
- DNS 只读诊断会检查凭据、检测 IP、读取域名及记录、说明将要做什么，**绝不会调用写 API**；独立回调诊断只验证本地配置/检测 IP，不发送回调或声称验证接收器/DNS。
- 同名多记录拒绝盲选。显式配置 `record_id` 后才能选择目标；既有记录使用其实际线路。
- 默认不创建不存在的记录；必须显式启用 `create_if_missing`。显式 ID 找不到时不会退化为创建。
- 凭据可在 Web 页面输入并保存，也可兼容环境变量；Web API 和导出不返回实际密钥。日志不输出 Authorization、签名、SecretId、SecretKey 或原始响应体。

> 已修复相对记录名与 FQDN 后缀碰撞的误选风险。已有部署应重新构建二进制并核对只读诊断中的区域/相对名/ID，详见 [名称作用域安全说明](<docs/name-scope-security.md>)。这不是已确认的真实账号事件。

## 快速开始

需要 Rust 工具链（项目使用 edition 2024，建议 stable 最新版本）。

```sh
cargo build --release
./target/release/ddns-rust
# 也可显式使用 ./target/release/ddns-rust serve
```

无需先运行 `init`、创建配置文件或设置任何环境变量。打开 `http://127.0.0.1:9876`，首次访问页面输入初始管理员账号、密码与确认密码；之后使用该账号登录。用户名为 1–64 字节，密码为 8–128 字节。没有默认账号或默认密码。

页面可配置更新间隔、超时、日志级别、提供商及其实际密钥、全部服务商/记录选项、域名、线路、TTL、记录 ID、IP 来源、启用/创建策略，以及服务监听地址、管理员账号/密码、可选 API Bearer Token。监听地址修改需重启生效；账号、密码或令牌修改后需要重新登录。直接填写的密钥只用于写入，保存后以“已配置”表示，页面/API 不回显；高级 JSON 与诊断导出不会包含实际密钥。腾讯云使用访问管理 API 的 SecretId/SecretKey，不要使用旧版 DNSPod 的 ID/Token。

首次启动自动生成安全空配置，重启自动加载；损坏或不可读的已有配置会报错，不会被默认值覆盖。管理员密码使用 Argon2id 哈希，账号与服务设置保存在配置旁的 `.web.toml` 伴随文件中。DNS 配置文件会保存网页输入的提供商密钥（非加密），请限制文件和备份访问权限；Unix 原子保存文件权限为 `0600`。浏览器使用 HttpOnly、SameSite=Strict 会话 Cookie，退出或重启服务后需重新登录。旧的环境变量配置和 Bearer Token 仍兼容，但不再是启动前提。

默认配置没有记录，**不会修改 DNS**。先在页面配置目标，再执行只读诊断；确认诊断报告正确后再执行真实更新。**只读诊断也会检查禁用记录，但真实更新会跳过禁用记录。**保存的启用记录会在下一个调度周期自动更新，因此初次配置保持 `enabled = false`，完成诊断后再启用。

```sh
# 验证 TOML 和字段，不联网
./target/release/ddns-rust check
# 只读诊断；JSON 报告到 stdout，日志到 stderr
./target/release/ddns-rust diagnose >diagnostic.json 2>diagnostic.log
# 明确执行一次真实更新；任一记录失败时退出码为 1
./target/release/ddns-rust once
# 指定配置路径（支持在子命令前后使用）
./target/release/ddns-rust --config /path/to/config.toml serve --listen 127.0.0.1:9876
```

## 系统服务

`-s install` / `--service install`：注册当前二进制、启用开机自启、后台启动，等待 Web 就绪后输出当前管理页地址并退出。`-s uninstall` / `--service uninstall`：停止后台服务并删除系统注册，保留二进制、配置、凭据和日志，无需配置路径。Windows 使用原生 SCM，Linux 使用 systemd，macOS 使用系统 LaunchDaemon。需要管理员权限；不会覆盖已安装的服务。

```sh
# Linux/macOS：先将二进制放到稳定目录
sudo ./target/release/ddns-rust -s install --config /path/to/config.toml
sudo ./target/release/ddns-rust -s uninstall
```

```powershell
# Windows：管理员 PowerShell
.\ddns-rust.exe -s install --config C:\ProgramData\ddns-rust\config.toml
.\ddns-rust.exe -s uninstall
```

系统服务不继承安装终端的临时环境变量，也不持久化 `--token`。配置服务环境、查看日志、重启和卸载的完整步骤见[服务安装说明](<docs/services.md>)。

## 配置示例

腾讯云配置参考 [原有示例](<config.example.toml>)；新增服务商参考 [Cloudflare](<examples/cloudflare.toml>)、[阿里云 DNS](<examples/alidns.toml>)、[DNSPod 传统 API](<examples/dnspod.toml>)、[Porkbun](<examples/porkbun.toml>)、[deSEC](<examples/desec.toml>)、[DNS.LA](<examples/dnsla.toml>)、[GoDaddy](<examples/godaddy.toml>)、[Vercel](<examples/vercel.toml>)、[NS1](<examples/nsone.toml>)、[Name.com](<examples/name_com.toml>)、[雨云](<examples/rainyun.toml>)、[ClouDNS](<examples/cloudns.toml>)、[dynv6](<examples/dynv6.toml>)、[Spaceship](<examples/spaceship.toml>)、[Gcore](<examples/gcore.toml>)、[NameSilo](<examples/namesilo.toml>)、[HiPM/HiDNS](<examples/hipmdnsmgr.toml>)、[华为云](<examples/huaweicloud.toml>)、[百度云 BCD](<examples/baiducloud.toml>)、[EdgeOne TEODNS](<examples/edgeone.toml>)、[火山引擎 TrafficRoute](<examples/trafficroute.toml>)、[独立回调](<examples/callback.toml>)、[Namecheap BasicDNS](<examples/namecheap.toml>)。每个服务商使用 `providers.kind` 指定类型，不是靠账号名称猜测。`record_id` 从本版起统一为字符串；旧腾讯云配置缺少 kind 或使用整数 ID 仍兼容，保存后会规范化为字符串。

域名要拆成服务商的**实际托管区域**和**主机记录**，不要使用公共后缀猜测。

- `domain = "example.com"`, `subdomain = "home"` → `home.example.com`
- 顶级记录使用 `subdomain = "@"`
- 子域托管区域可用 `domain = "sub.example.com"`, `subdomain = "home"`
- `subdomain` 始终是相对记录名，允许多级主机：`home.example.com` 在 `example.com` 区域表示 `home.example.com.example.com`，不是自动识别的完整域名。各适配器明确声明 API 名称约定，避免后缀碰撞误选；不会通过裁剪区域后缀猜测主机。
- A 与 AAAA 分别配置记录；同一 IP 来源的网络请求按记录类型绑定 IPv4/IPv6。
- `record_line` 默认是腾讯云 API 的 `默认`；有 RecordId 时保留选中记录的实际线路。
- TTL 仍受腾讯云套餐的最小值限制，API 会返回明确错误。

IP 来源：

| kind | value | 说明 |
| --- | --- | --- |
| `url` | `https://api.ipify.org` | HTTPS 纯文本 IP 接口；A 走 IPv4，AAAA 走 IPv6；禁止 URL 用户信息、查询参数与重定向 |
| `static` | 公网 IPv4/IPv6 | 用于隔离“检测 IP”和“云 API”故障，也支持手工指定公网地址 |
| `interface` | `eth0` / `en0` / `Ethernet` | 在指定网卡上按 A 选 IPv4、按 AAAA 选 IPv6，可用 `regex` 过滤公网地址 |

Linux、macOS 和 Windows 的管理页会列出已分配 IP 的服务端网卡，并显示所选网卡上与记录类型对应的地址。网卡来源的可选字段 `regex` 使用 Rust 正则语法，匹配页面显示的 IP 文本（IPv6 为压缩格式）。留空时匹配所有同协议公网地址。页面会预览匹配结果并标出将使用的地址。多个匹配时，按 IP 数值升序取第一个。没有匹配时，该记录报错并跳过更新。

```toml
[records.ip_source]
kind = "interface"
value = "en0"
regex = '^240e:'
```

不会发布私有、回环、链路本地、CGNAT 或文档示例地址。接口处于家庭 NAT 后时通常没有公网 IPv4，应使用 HTTPS 来源。

Web 配置默认可直接填写实际凭据；也可通过高级环境变量引用使用服务商对应的大写环境变量名称（`TENCENT_` / `CLOUDFLARE_` / `ALIDNS_` / `DNSPOD_` / `PORKBUN_` / `DESEC_` / `DNSLA_` / `GODADDY_` / `VERCEL_` / `NS1_` / `NAMECOM_` / `RAINYUN_` / `CLOUDNS_` / `DYNV6_` / `SPACESHIP_` / `GCORE_` / `NAMESILO_` / `HIPM_` / `HUAWEICLOUD_` / `BAIDUCLOUD_` / `EDGEONE_` / `TRAFFICROUTE_` / `CALLBACK_` / `NAMECHEAP_`）或通用 `DDNS_` 前缀。多个账号可使用不同变量名，进程启动后改变环境变量需要重启。Cloudflare、deSEC、Vercel、NS1、雨云、dynv6、Gcore、NameSilo、HiPM 和独立回调使用 `token_env`，其他当前已支持服务商使用 `secret_id_env` / `secret_key_env`；这里的字段只表示引用名称，具体密钥格式由服务商决定。

Cloudflare 建议 `ttl = 1`（自动），代理记录必须自动 TTL；`records.options.proxied` 只用于创建，更新保留现有代理状态。阿里云的线路 `默认` 会映射为 `default`。没有线路概念的服务商忽略 `record_line`，但仍要求多条匹配记录时指定 ID。传统 DNSPod 只支持主账号 ID/Token，不能使用腾讯云 SecretId/SecretKey。

## 服务商专属安全限制

当前目录有 24/29 项已实现：**23 个可读取的 DNS 适配器 + 1 个独立未验证回调能力**，不是 24 个可验证远端 DNS 的适配器。最终完整进度见[服务商清单](<PROVIDERS.md>)。

- **火山引擎 TrafficRoute**：不是腾讯云 DNSPod、GTM、PrivateZone、HTTPDNS 或递归公共 DNS。固定当前官方 `dns.volcengineapi.com`、`cn-beijing/dns` 签名与 `2018-08-01` API，要求显式 public_dns 范围和原生正十进制 ZID。区域须主区域、Stage=0、服务商报告 NS 正确；记录为跨线路单值静态 A/AAAA、非加权 RRset、无 GTM 标签。TTL 1–86400，还需满足实际 TradeCode 套餐最低值（通过读取验证，不猜测配置套餐）。只管理原生标准线路。UpdateRecord 只发送既有 Host/Line/RecordID 与新 Value/TTL；官方明确省略 Type/Remark/Weight 保留。完整写前/写后验证仍不能代替原子 CAS，需唯一写入者。
- **Namecheap**：使用账户 API User/Key，不是 Dynamic DNS 密码；实际 API 服务器公网 IPv4 白名单可通过网页的 `credentials.client_ip_env` 直接填写，或通过 `NAMECHEAP_` 环境引用提供，不能使用 DDNS 目标 IP。显式 SLD/TLD 与 production/sandbox，不猜公共后缀或回退端点。仅全活动、无 DDNS/关联元数据的普通 BasicDNS 快照；**setHosts 替换整个区域主机数组**，必须明确唯一写入者，绝非原子单条更新。省略 EmailType 保留既有邮件模式，所有无关行/重复项完整保留；800 上限，TTL 60–60000，初始规范数值/非 MX 的 MXPref=10 是适配器子集限制。原生 HostId 可轮换，配置只接受稳定逻辑 ID。详见[第一方契约纠正与限制](<docs/namecheap-sdk-contract-update.md>)。
- **独立回调**：仅固定 Bearer JSON POST、网页直接配置或服务器 `CALLBACK_` 环境引用的 HTTPS 端点、显式 `unverified/every_run/metadata_only` 确认，不是上游任意 GET/模板 URL 的兼容模式。每次真实执行都会投递，IP 未变也重复；接收器幂等性不保证。诊断零回调请求；HTTP 2xx 只报告“接受/未验证”，不报告 DNS 更新成功，TTL 仅元数据。不能配置远端记录 ID 或创建记录。详见[回调能力说明](<docs/callback-capability.md>)。

- **华为云 DNS**：必填 SDK 允许的 `region` 和区域 IAM `project_id`，可选原生 `zone_id`（记录和提供商配置必须一致）；只管理 PUBLIC/ACTIVE/default_view、weight=1、非系统静态单值 RRset。保留描述等合法字段，拒绝别名/健康检查/未知路由。API TTL schema 上限 2147483647，但本应用全局上限 604800 更严格；保守下限 300 不是宣称的账户最小值，不静默钳制。POST/PUT 异步 202 后一次读回必须 ACTIVE 且设置一致，否则报告 pending/uncertain，不自动重试。非默认企业项目建议显式 zone_id；仅永久 AK/SK。
- **百度云 BCD**：仅注册域名产品，不等于所有 BCE DNS。必填实际 `resource_id`，精确匹配 RUNNING、未过期域名和文档定义的百度 NS 对；这不是实时公网委派探测。原生记录 ID 为正 int32 十进制字符串；实际线路 DEFAULT/CMNET/CNC/EDU/SEARCH，TTL 60–3600。普通单记录编辑只修改值/类型/TTL；未知权重/备注设置拒绝。文档规定写回执为空 HTTP 200，必须全量读回验证，不能伪造 RecordId 回执。
- **EdgeOne**：只支持 NS/full 站点原生 TEODNS，不支持 Origin/OriginGroup、partial/CNAME/DNSPod/Pages 模式，不回退其他产品。必填 `mode=dns`、`scope=teodns`、`api_version=2022-09-01`、`zone_id`。TTL 60–86400、原生 `record-...` ID，更新仅发送 RecordId/Content/TTL，保留实际 Location/Weight 等设置。必需读取 DescribeZones、DescribeDnsRecords、DescribeAccelerationDomains、旧版 DescribeApplicationProxies，以排除托管流量/主机代理冲突；旧 API 不可用或无权限时安全拒绝，不降级跳过。无原子条件写入，需唯一写入者。

- **NameSilo**：官方 API 所有操作均为 GET，密钥不可避免地出现在查询参数中；端点固定、禁用重定向，传输诊断避免输出 URL。每次更新都会轮换原生 ID，因此配置使用稳定的 `namesilo-<SHA256>` 逻辑 ID，诊断保留实际原生 ID；写前/写后验证原生 ID 更换、旧 ID 消失和兄弟记录不变。只管理 Active、DNSOWL 基础 DNS 的单值 A/AAAA，保守 TTL 300–604800，拒绝有特殊自动调整政策的 3603/7207。API 读回不等于 DNS 传播完成。
- **HiPM / HiDNS**：自托管管理器没有全局服务端点。必填 HTTPS origin（可附 `/api`），可在网页直接填写到 `providers.credentials.endpoint_env`，或使用 `providers.options.endpoint_env` 引用服务器 `HIPM_` 环境变量（例如 `HIPM_API_ENDPOINT`）。Web 可保存但不返回实际 URL，不提供关闭 TLS 校验或任意 URL 模板选项。只支持已审计的启用 Aliyun 账户映射，不宣称所有底层服务商通用兼容。`record_line` 必须为真实原生线路代码，例如 `default`，不把 `默认` 猜测转换为线路。更新明确传 TTL/line，省略 status/weight/remark 以保留单独控制；写后验证全部控制和兄弟记录。上下文证明覆盖账户绑定 ID/类型/活动状态，而非同 ID 下未变更的底层密钥；排除账户配置以免泄漏。仍需唯一写入者。

- **dynv6**：只管理明确的子记录，不修改 `@` / 区域主 IPv4 / IPv6 prefix，拒绝继承地址、MAC 和后缀型记录。REST 没有 TTL 读写，必须显式设置 `providers.options.ttl_mode = "provider_default"`；配置 TTL 不生效、不会伪造实际 TTL，也不会因 TTL 差异写入。固定原生记录身份与内容在 PATCH 前后验证。
- **Spaceship**：只更新自定义单值 A/AAAA 集合，ID 是稳定的合成 RRset ID，不是原生记录 ID。TTL 范围 60–3600。地址更新先新增并验证，再按精确旧值删除，永远不使用 `force=true` 或整组删除。操作非原子，失败可能保留双值并阻止后续自动更新，须人工恢复。域名信息限流为每域名 300 秒 5 次；一次地址更新需 4 次详情读取，建议间隔至少 300 秒，多记录仍可能触发限流。
- **Gcore**：只更新启用的静态单值 RRset，元数据仅支持空对象或字符串备注；路由、备用、健康检查、CDN 和未知控制拒绝。PUT 会完整替换 RRset，因此原生成员 ID 不用于配置，使用稳定合成 ID；备注原样保留。Free/Pro/Enterprise 最低 TTL 为 120/30/1 秒，`providers.options.plan` 是操作者对真实套餐的声明，不是 API 查证的账户资格，实际账户政策仍可能拒绝。区域读取不构成独立权威委派/主从角色证明；未指示 secondary 不等于线上验收。

- **Name.com**：当前 Core v1 API，用户名/API Token Basic 认证，TTL 最少 300 秒；记录 PUT 是完整替换，因此只支持可保留全部字段的普通 A/AAAA。写前按 ID 重读，保留实际 host/type/priority；未知设置会拒绝，需唯一写入者。账号域名读取不等于独立权威 NS 验证。
- **雨云**：必填 `providers.options.domain_id`，且实际产品 ID/域名匹配、雨云报告默认权威 NS 且未 hold。TTL 按官方客户端允许列表检查，更新保留实际线路与 level；暂停、产品绑定、未知状态/设置拒绝修改。只创建 DEFAULT 线路。写前全量重读、写后全量验证；最终一致性可能造成 `UnverifiedWrite`，应人工检查，不自动重试。官方响应 schema 未完整定义，布局变化会安全拒绝。
- **ClouDNS**：使用官方 `add-record` / `record-type` 和 `mod-record` / `record-id`，而不是旧版示例中的不一致接口。支持 API 用户、子用户 ID/用户名认证；只管理普通 master 区域、静态记录，拒绝 GeoDNS/failover。TTL 必须在 API 返回的可用集合中；更新不提交 status/note/failover。写前重读但无原子 CAS，需唯一写入者。官方区域信息未提供具体成功样例，当前活动状态只接受明确 1/true；其他响应布局会安全拒绝，兼容性仍需真实账号确认。

- **GoDaddy**：只更新专用单值 A/AAAA RRset。API 的 404 也可能表示无权查看，所以不会被当作记录不存在；只对已验证域名下明确返回空列表的记录集允许显式创建。写入前重读并检查过期状态，不支持原子 CAS，请使用唯一写入者。当前官方文档允许至少一个域名或具备管理资格的套餐，旧 `sso-key` 认证标记为弃用但仍提供兼容；准确权限/资格问题由原始 API 错误返回。
- **Vercel**：使用当前官方 v5 记录列表、v2 创建、v1 PATCH；可配置 `providers.options.team_id`。区域必须已验证且由 Vercel DNS 管理，系统/只读记录及 CNAME/ALIAS/子域 NS 冲突会拒绝更新；PATCH 仅发送值与 TTL，保留其他设置。期望 TTL 范围为 60..604800，不静默修改。
- **NS1**：支持默认主区域中的专用静态单答案 RRset，保留静态答案元数据。多答案、过滤器、区域路由、数据源 feeds、链接、secondary 和 split-horizon 区域均拒绝通用 DDNS 修改。写入前重读，仍需唯一写入者；原始 API 的明确 `record not found` 才可表示缺失记录，不把其他 404 当作空记录。

- **deSEC**：仅更新单值 A/AAAA RRset；多值集合会拒绝更新，避免误删其他地址。RecordId 是诊断报告中的合成 RRset ID。TTL 必须满足域名的 `minimum_ttl`，写入前再读一次以发现过期状态，但 API 没有原子条件更新保证；请为目标 RRset 配置唯一写入者。
- **Porkbun**：按记录 ID 更新，不使用会替换同名全部记录的接口。API 不公开账号精确最小 TTL，本地保守要求至少 600 秒，更高套餐限制由原始错误返回。写入产生警告时不会报告无条件成功；还需确认域名实际使用 Porkbun 权威 DNS。
- **DNS.LA**：使用官方当前 HTTPS API，保留线路、组和权重元数据。暂停或引用他人解析的区域拒绝更新。自动创建目前仅支持默认线路；其他线路可用显式 RecordId 或实际 `lineCode` 选择已有记录，不猜测新线路 ID。

## 排错流程：腾讯云查询域名失败

1. 把日志等级调成 **debug**，点 **只读诊断**。
2. 确认 `stage`：`credentials` / `ip_detection` / `DescribeDomain` / `DescribeRecordList` / `selection` / 写入 API。
3. 根据 `code` 和 `hint` 检查：
   - `MissingCredentials`：网页实际密钥未填写且引用的环境变量未设置，或使用了旧版 DNSPod Token。
   - `AuthFailure.*`：检查 SecretId/SecretKey、服务器 UTC 时间/NTP、CAM 权限和账号归属。
   - `UnauthorizedOperation.*`：子账号须有 DNSPod 对应区域及动作权限。
   - 域名不存在：`domain` 应是托管区域，检查是否在另一账号，不能把完整主机名误写为区域。
   - `Ambiguous*` / 多条候选：在配置指定 RecordId，不要把诊断当成“自动选第一条”。
   - `IpSourceTimeout` / `IpFamilyMismatch`：确认机器 IPv4/IPv6 连通性与 IP 来源，改静态 IP 复测。
4. 把 `request_id` 交给腾讯云支持；把 `run_id` 用于过滤本地日志。
5. 导出诊断 JSON，分享前检查域名、公网 IP、RequestId 与 API message 等信息。自动脱敏保护密钥，不代表隐藏所有业务信息。

诊断返回的 `would_update` / `would_create` 只是计划，不证明账号具有写权限，也不验证修改后的 DNS 传播。真实更新成功仅表示 API 接受请求，不保证递归 DNS 缓存已刷新。

## 日志与可靠性

- stderr 输出单行英文 JSON，可交给 journald、Docker logging 或日志平台；进程内保存最近 1000 条供页面检索，**重启会清空页面历史**。
- debug 记录 API 动作、HTTP 状态、耗时、RequestId 与记录执行结果；保留脱敏的原始 API Error.Message 和网络错误原因链，不会开启第三方 HTTP 库的原始 debug 日志。
- 默认不自动重试写请求，避免“响应超时但服务端已经修改”造成重复操作；后续调度重新读状态再决定。`retryable` 是提示，不是已经重试。
- 配置保存采用同目录临时文件 + 文件同步 + 原子替换。配置文件包含目标域名、环境变量引用及网页输入的实际密钥，应限制权限并保护备份。
- 不重叠执行，忙时返回 HTTP 409；关闭页面或请求取消不会中断已经开始的更新。
- 调度在服务启动后等待一个完整周期；保存配置会重置等待。Ctrl+C 或 Unix SIGTERM 等待活动操作完成（容器停止宽限期应设置足够长）。
- API 响应和 IP 检测响应均有大小限制；不关闭 TLS 证书校验；关闭重定向以防签名泄漏。

## Web 安全

默认仅监听 loopback，业务 API 需要账号会话或可选 `Authorization: Bearer <token>`（至少 24 字节）。只有静态页面、健康检查、初始化状态、首次设置账号和登录/退出入口公开；设置账号在初始化后拒绝重复调用。认证尝试每分钟最多 10 次，会话有效期 24 小时，修改账号/密码/令牌会使已有会话失效。修改请求拒绝跨 Origin；反向代理应保留与外部访问一致的 Host。首次初始化前请勿将未保护的服务暴露到不可信网络，以免管理员被抢先注册。

不要直接暴露明文 HTTP 到公网。远程使用应放在 **HTTPS 反向代理 / VPN + 防火墙** 后，妥善设置代理超时（多条记录逐条执行可能较久）。这不是多租户管理系统，管理员能够配置受信任的 IP 来源 URL；不要把管理员令牌交给不可信用户。

## API

```sh
curl -H "Authorization: Bearer $DDNS_RUST_WEB_TOKEN" http://127.0.0.1:9876/api/status
curl -H "Authorization: Bearer $DDNS_RUST_WEB_TOKEN" -H 'Content-Type: application/json' \
  -d '{"dry_run":true}' http://127.0.0.1:9876/api/run
curl -X PUT -H "Authorization: Bearer $DDNS_RUST_WEB_TOKEN" -H 'Content-Type: application/json' \
  -d '{"level":"debug"}' http://127.0.0.1:9876/api/log-level
```

`GET /api/auth/status` 返回是否初始化；`POST /api/auth/setup` 首次设置账号，`POST /api/auth/login` 登录（均接收 `username/password`），`POST /api/auth/logout` 退出。`GET/PUT /api/settings` 配置监听地址、管理员与可选令牌，并返回当前实际监听地址；命令行 `--listen` 或 `--token`/环境令牌仍作为显式覆盖，使用它们时应移除覆盖并重启，才能让相应网页设置完全生效。

`GET /api/providers` 返回服务商目录和凭据/选项能力（包含未实现的进度项，`implemented=false` 不可执行）；`GET/PUT /api/config` 读写配置，密钥位于每个提供商的 `credentials` 映射中，响应仅返回 `__DDNS_CONFIGURED__` 占位。原样提交占位保留该提供商已有值，提交空字符串删除，真实值替换；更名或换类型不能沿用占位。`GET /api/logs?level=debug&search=<run_id>` 获取最小级别以上日志；`GET /api/status` 获取最后一次运行。诊断结果中的记录失败仍返回 HTTP 200 报告（必须检查 `results[].error`）；请求格式或字段校验错误为 400/422（过大请求为 413），认证失败为 401，运行繁忙为 409。

## Docker

```sh
docker build -t ddns-rust .
# 命名卷自动使用容器 /data 的权限，无需预建配置或密钥 env 文件
docker run --rm --name ddns-rust \
  -p 127.0.0.1:9876:9876 \
  -v ddns-rust-data:/data ddns-rust
```

容器用非 root UID 10001；宿主机挂载目录与配置需要允许 UID 10001 写入（否则可只读挂载，但页面保存与日志等级持久化会失败）。应挂载**目录**，不要仅 bind-mount 单个配置文件，因为原子保存需要替换文件。可在启动前 `chown -R 10001:10001 data`。interface 来源观察的是容器网络接口，不是宿主机；通常使用 url 来源。

## 开发验证

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
node --check web/app.js
node --test tests/web_config.test.js
```

测试使用本地模拟腾讯云、Cloudflare、阿里云、传统 DNSPod、Porkbun、deSEC、DNS.LA、GoDaddy、Vercel、NS1、Name.com、雨云、ClouDNS、dynv6、Spaceship、Gcore、NameSilo、HiPM DNS Manager（仅 Aliyun 映射）、华为云 DNS、百度云 BCD、腾讯云 EdgeOne（原生 TEODNS）、火山引擎 TrafficRoute、Namecheap BasicDNS 的 HTTP 服务和独立回调接收器，不需要真实密钥，不向真实 DNS/回调端点请求。本次零配置改造通过 **Rust 全量单元/CLI/真实启动测试和 47 Web VM 测试**，包括首次账号设置、会话退出/失效、重启持久化、密钥遮罩和真实二进制无配置启动；严格 Clippy、格式检查和 Release 构建通过。此前服务商批次还通过 24 份 Release 配置检查和 41 请求的本地 HTTP 冒烟；没有真实账号、DNS 传播或浏览器视觉验收。完整限制与批次证据见[全量进度](<PROVIDERS.md>)。项目从 ddns-go 的使用场景与 MIT 开源实现中获得启发，Rust 实现为新编写；保留上游版权说明。
