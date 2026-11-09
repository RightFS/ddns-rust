# 服务商接入进度

目标：以当前上游 ddns-go 的 [服务商选择表](<../ddns-go/dns/index.go#L64-L122>) 中 29 种类型为基准，全量分批接入。

**完成标准不是“有文件/有选项”**：适配器必须真实接线；响应错误应保留脱敏详情；可读取的记录列表需完整分页；禁用/重复/显式 ID 不匹配应拒绝误更新；只读诊断不允许写请求；必须通过模拟 API 回归测试与构建。没有真实账号时，只能声明本地模拟验证，不能声明线上验收。

## 当前批次

第一批已完成：腾讯云兼容架构重构 + Cloudflare + 阿里云 DNS + DNSPod 传统 API。统一验证通过：**118 项 Rust 测试（113 单元/模拟 API + 5 CLI）、严格 Clippy、Release 构建与 JavaScript 语法检查**。

第二批已完成：Porkbun、deSEC、DNS.LA。累计 **184 项 Rust 测试（179 单元/模拟 API + 5 CLI）**、严格 Clippy、Release 构建与 JavaScript 检查通过；真实本地 HTTP 测试验证了 29 种类型目录、7 个可用适配器、字符串 ID、配置持久化和无写入诊断。所有示例配置通过检查。测试临时服务已停止。

第三批已完成：GoDaddy、Vercel、NS1。累计 **249 项 Rust 测试（244 单元/模拟 API + 5 CLI）**、严格 Clippy、Release 构建、JavaScript 检查全部通过。真实本地 HTTP 测试验证了 10 个可用适配器、Vercel team_id 与记录 UID 持久化、凭据缺失诊断、禁用跳过以及无效选项拒绝；全部示例配置通过检查，临时服务已停止。

第四批已完成本地验证：Name.com、雨云、ClouDNS。累计 **307 项 Rust 测试（302 单元/模拟 API + 5 CLI）**，严格 Clippy、Release 构建、Rust 格式检查与 JavaScript 语法检查通过；13 份当前可用配置（含原有配置示例，已按实际文件数校正）全部通过 CLI 检查。新增 15 项 Name.com、17 项雨云和 24 项 ClouDNS 模拟 HTTP 测试，并补充配置/API 往返及 provider-managed TTL 能力回归。Release 二进制的真实本地 HTTP 冒烟验证通过：29 种目录、13 个可用适配器，三个新服务商的产品 ID/认证类型/字符串记录 ID 配置持久化、缺失凭据只读诊断、禁用跳过及无效选项拒绝。临时本地服务已停止，没有真实云 DNS 请求或写入。

**全量状态：24/29 项已实现并完成本地接线验证（82.8%）：23 个可读取的 DNS 适配器 + 1 个独立未验证回调能力。剩余 5 项未开放：阿里云 ESA、Dynadot、Now.cn、Eranet、Tnet.hk；缺失契约证据的项目不计为完成。线上账号验收不在本轮验证范围内。** 雨云官方接口没有完整响应 schema，已核对官方客户端布局；ClouDNS 官方区域信息未提供具体成功响应样例，区域活动状态当前只接受明确 1/true，其他布局会安全拒绝，仍需真实账号确认响应兼容性。不能据此声明所有套餐/账号可用。

第五批已完成本地验证：dynv6、Spaceship、Gcore。累计 **368 项 Rust 测试（363 单元/模拟 API + 5 CLI）**、**6 项 Web 配置逻辑回归**，严格 Clippy、Release 构建、格式及 JavaScript 语法检查通过；按实际文件清单计 **16 份可用配置** 全部通过 CLI 检查。新增 dynv6 16 项、Spaceship 18 项、Gcore 24 项模拟 HTTP 测试，覆盖原生字段/稳定合成 ID、写前状态变化、非原子写后验证、错误详情与脱敏。Release 真实本地 HTTP 测试验证 29 项目录/16 个可用适配器、TTL 能力确认/套餐/字符串 ID 配置持久化、缺失凭据诊断、禁用跳过、错误选项与线路别名重复目标拒绝、打包页面警告。临时服务已停止；没有真实云 DNS 请求或写入。Web 回归采用实际脚本的 VM/DOM 桩，不是视觉浏览器验收。

第六批已完成本地验证：NameSilo 与 HiPM DNS Manager（HiDNS）已接线。该批累计 **427 项 Rust 测试（422 单元/API + 5 CLI）**、**11 项 Web 配置逻辑测试**，严格 Clippy、格式检查和 Release 构建通过；**18 份已实现配置**通过 CLI 检查。Release 真实本地 HTTP 冒烟验证 29/18 目录、配置与字符串 ID 持久化、缺失凭据/缺失或无效 HiPM 端点诊断、禁用真实运行及 12 类无效配置拒绝；测试服务已停止，没有真实云 DNS 请求。HiPM 仅支持已审计的 Aliyun 映射，端点只能来自服务器 `HIPM_` 环境变量引用。Dynadot 暂缓：官方 v1 是整区替换，v2 为 Beta 且响应/请求描述存在矛盾；不把未验证的更新 URL 或空适配器列为完成。

**名称作用域安全修复（2026-11-09）**：审查发现旧的“相对名或 FQDN 任一匹配”可能误选后缀碰撞记录。通用协调器现在要求每个适配器明确声明 `NameFormat::Relative` / `Fqdn`，在候选计数和显式 ID 校验阶段只采用正确约定。HiPM 的 Aliyun RR 始终按相对名追加区域，保留原生 RR 写入；Vercel 子域委派判断也按相对名处理。新增 15 项通用/服务商安全回归及 4 项 HiPM 回归，涵盖错误主机不得写入、相等 IP/诊断不得误报、显式 ID 不回退、后缀碰撞不造成误选、合法多级相对名仍可更新。

第七批已完成配置/Web 接线和本地统一验证：华为云 DNS、百度云 BCD 与腾讯云 EdgeOne。累计 **499 项 Rust 测试（494 单元/API + 5 CLI）**、**19 项 Web VM/DOM 桩配置回归**通过；严格 Clippy、格式检查、JavaScript 语法和 Release 构建通过，**21 份已实现配置（原有示例 + 20 个服务商示例）**通过 Release CLI 检查。新增华为云 18、BCD 10、EdgeOne 22 项模拟 API 测试以及 3 项配置测试，API 配置往返测试扩展覆盖原生 ID/区域选项/缺失凭据/禁用运行和错误配置拒绝。华为云日志脱敏断言已隔离到子测试进程，避免并行日志等级回归污染，保留完整正向与脱敏断言。当前可用目录为 21/29；未进行真实账号或 DNS 传播验收。Release 实际本地 HTTP 冒烟通过：29 项目录/21 个可用服务商、21 份示例合并的 22 条禁用记录，缺失凭据只读诊断、全部禁用真实运行、14 类错误配置 HTTP 400 且持久化不变。临时本地服务已正常停止，没有真实云请求。

## 第八批与独立回调验证

火山引擎 TrafficRoute 与独立 JSON POST 回调已完成接线及本地验证。累计 **535 项 Rust 测试（530 单元/API + 5 CLI）**、**27 项 Web VM/DOM 桩测试**通过，严格 Clippy、格式检查、JavaScript 语法和 Release 构建通过。**23/23 份明确列出的已实现配置**通过 Release CLI 检查（原有示例 + 22 个服务商/能力示例，未将未来不可用示例计入）。

Release 实际本地 HTTP 冒烟通过：29 项目录、23 项可用能力、22 项 supports_dns_read；27 条禁用记录全部在真实运行中跳过。缺失凭据/缺失与无效回调端点在 IP 来源请求之前拒绝；合法回调诊断通过真实 engine 分支返回 `would_call_unverified`，不发送回调，不伪造 RecordId 或 previous_ip。无效 callback ID/创建/选项配置返回 400，持久化字节不变；打包 JavaScript 显示双语 UNVERIFIED 警告。测试服务已停止，所有任务输出已收集，没有真实云 DNS 或回调端点请求。

TrafficRoute 是**火山引擎**产品，使用当前官方 DNS 端点和签名，不是 Tencent/DNSPod；之前目录中的错误归属已纠正。它只管理主区域、原生标准线路、跨线路单值且非加权/GTM 的记录，TTL 最低值根据实际 TradeCode 读取核对，写入按官方省略字段保留合同执行。[独立回调](<docs/callback-capability.md>)不实现 DNS Adapter，HTTP 2xx 仅表示 HTTP 接受，不能当作 DNS 更新或业务成功；每次真实运行都再次投递，TTL 仅元数据，接收器幂等性未知。

## 第九批 Namecheap 验证与契约纠正

Namecheap 窄范围适配器已完成真实接线，累计 **558 项 Rust 测试（553 单元/API + 5 CLI）**、**32 项 Web VM/DOM 桩测试**通过；严格全目标 Clippy、格式、JavaScript 语法与锁定依赖的 Release 构建全部通过。新增 19 项 Namecheap 回归、3 项 Config 与 1 项隔离进程 API 测试，未将占位实现或未开放项目计数。**24/24 份明确选择的 Release 配置**通过（原有示例 + 23 个已实现能力示例）。

实际本地 Release HTTP 冒烟 **41 个请求**通过：29 项目录、24 项可用能力、23 个 DNS 读取器和独立回调；24 个合成服务商配置、25 条禁用记录真实运行全部跳过，无云端请求。检查凭据缺失、服务器 ClientIp 缺失/无效、错误账户、私有 IPv4/IPv6 在 IP 来源之前拒绝，报告 IP 为 None；保存只含引用与稳定逻辑 ID，不泄露合成密钥/IP。21 类语义错误返回 400、TTL JSON 类型错误维持既有 422，持久化字节均不变；已打包双语整区替换和 UNVERIFIED 提示、安全头验证通过。服务已终止，全部后台任务已收集。

[第一方 SDK 新证据](<docs/namecheap-sdk-contract-update.md>)推翻了此前 Namecheap 邮件/字段/编码证据不足的泛化暂缓：省略 EmailType 保留原邮件模式，真实 XML 暴露活动/DDNS/关联应用字段，form POST 合同和 800 记录上限均已核实。初始只支持全活动、无 DDNS/关联元数据、普通 BasicDNS 完整快照；规范数值与非 MX 的 MXPref=10 是本适配器保守子集限制，不是宣称服务商只允许这些值。写入替换整个主机记录数组，必须明确唯一写入者，省略邮件模式字段，完整写前/写后对比，不支持自动重试或原子 CAS。稳定 `namecheap-64hex` 是逻辑主机/类型身份，不是原生 HostId；其他行地址字符串和重复项完整保留。不是 Dynamic DNS A-only 更新 URL，也不是任意 Namecheap DNS 模式的兼容承诺。

## 后续安全门禁与 Dynadot 复审

新增[可用性回退门禁回归](<src/providers/availability_tests.rs>)：覆盖所有未开放类型与未知/路径形态类型，直接绕过 Config 验证调用凭据检查和协调入口，两种诊断/真实模式均在 registry 门禁返回 UnsupportedProvider；本地代理连接计数为零，不修改或输出环境值。现累计 **559 项 Rust 测试（554 单元/API + 5 CLI）**、32 项 Web VM 测试通过；锁定依赖的严格 Clippy、格式、Release 构建及明确列出的 24 份 Release 配置再次通过。本轮没有新增服务商可用计数，上一批 41 请求 HTTP 冒烟是历史验证，不冒称本轮重跑。

[Dynadot v2 第二轮复审](<docs/dynadot-v2-second-opinion.md>)重新获取完整官方机器文档，并区分可处理的差异与破坏性操作缺口：命令专属 DELETE JSON 可以覆盖通用无 body 指引；有限 flags/mode 差异可显式解析；真正未证明的是删除匹配/默认值、同主机追加共存、单独子记录 payload 与全局 TTL/邮件设置保留。新增 required-main-list 与 same-subhost-unique 错误线索不等于已证明追加不可能。没有发现有来源的 v2 活动 DNS 捕获样例，不复制停车模式占位数据或第三方模拟响应为真实契约。

## 后续 CLI 边界与三家原生状态证据

新增[真实 CLI 回归](<tests/cli.rs>)覆盖全部五项未开放类型：启用/禁用记录分别执行 check/diagnose/once，均在配置可用性门禁拒绝、不输出 DNS 报告且配置字节不变；伪造 provider.implemented=true 为未知字段，不能把客户端声明当作服务器能力。共 35 个子进程场景，未请求云端。累计 **560 项 Rust 测试（554 单元/API + 6 CLI）**、32 Web VM 测试、严格 Clippy/格式/Release 再次通过；没有新增可用服务商。

[三家独立第一方前端复审](<docs/registrar-state-contract-review.md>)有实质新证据：各自当前文档 www/lowercase GET 与前端 DescribeRecordIndex 的 origin/path/method 一致，原始 Data 直接渲染，state=0 正常且提供 Disable，2 暂停且提供 Enable，3 管理暂停、4 待审、5 驳回；不存在 State=1 活动证明。相同路由不能被武断称为不同 BFF，亦不能自动证明其 HMAC/legacy/auth-context 响应等价。前端 GET 使用 currentPage/pageSize 与 Data/Pagination；同主机 POST 更新传 Mx/Ttl/Line，但省略 State/Remark，remark 还可能是驳回诊断。这些缩小签名上下文/完整页规则/GET 保留与正回执的证据请求，不能照搬分页、导出、Status setter 或将 UI 省略变成服务器保留保证。

## 当前工作区最终核验与外部证据需求

三轮自动继续分别完成 Dynadot 新源复审、三家状态/分页前端复审及独立可行性复核。实现仍是 **24/29**，没有把缺失语义的草稿、停车模式样例或 write-only 更新 URL 算作完成。最终完整工作区验证实际为 **579 项 Rust（568 单元/API + 10 CLI + 1 真实启动）和 47 Web VM**，严格 Clippy、格式、Release 构建和 JS 语法通过；其中新增账号/凭据/服务功能来自并行工作区更新，不能把旧 560/32 计数冒称为当前总数。记录见[本轮测试日志](<target/round3-tests.log>)；本轮未做真实云 DNS、回调或传播验收。

独立复核确认不应把 CAS、全部特性、官方 SDK 存在、原生 ID ACK、State=1 或非法 GET-only echo 设为普遍前置。Dynadot ALL-family singleton owner 可缩小匹配歧义，明确中断接受的 delete-before-add 可避开共存要求，但仍缺活动完整 DNS/全局设置与一个合法局部 POST 的保留合同。ESA 普通 unproxied 单 IPv4 的 Data.Tags/适用缺失设置语义仍需分类。三家当前状态 0/2 证据有效，仍缺本品牌 HMAC 上下文的完整页/平台模型和窄 GET 更新的字段语义；类型明确的空 error 加完整严格读回可以证明收敛，缺 ID ACK 本身不是绝对阻塞。

这些核心语义缺口连续三轮仍未补齐，仓库没有可用的真实接口离线 fixture；继续写入接线将需要猜测缺失设置、分页完成或不明保留行为，违背本项目完成标准。可按[最小离线证据请求](<docs/remaining-provider-evidence-request.md>)提供任一家的已有脱敏材料或明确服务商规范后，继续该家窄范围实现；不要求提供凭据或新发生产试写。全量目标未完成。

通用协调器已提供显式 provider-managed TTL 能力；dynv6 的无 TTL 读写不会被伪造成实际 TTL。Spaceship 的非原子地址替换及 Gcore 的单值/备注元数据限制详见下表与说明。

- 通用协调器：[common.rs](<src/providers/common.rs>)，集中实现安全选择、幂等比较、只读计划和详细 HTTP 错误脱敏。
- 服务商目录：[registry.rs](<src/providers/registry.rs>)，`implemented=false` 项不会成为可用选项，也不会回退到腾讯云/阿里云。
- 不同服务商 RecordId 统一以**字符串**保存，仍接受旧腾讯云配置中的整数输入。
- 不改动既有记录的代理状态、解析线路、备注/标签或禁用状态。各适配器仅提交所需写字段。

## 全量清单

| kind | 服务商 | 状态 |
| --- | --- | --- |
| tencentcloud | 腾讯云 DNSPod API 3.0 | 原有已验证适配器；兼容迁移 |
| cloudflare | Cloudflare | 第一批本地模拟验证通过 |
| alidns | 阿里云 DNS | 第一批本地模拟验证通过 |
| dnspod | DNSPod 传统 API | 第一批本地模拟验证通过 |
| aliesa | 阿里云 ESA | 暂缓；原生组合 A/AAAA、IPv6 契约矛盾，省略字段保留未证明；见 [契约审查](<docs/aliesa-contract-notes.md>) |
| trafficroute | 火山引擎 TrafficRoute | 第八批本地模拟验证通过；主区域/标准线路/跨线路单值/无加权 GTM，按实际套餐 TTL 限制读取验证 |
| dnsla | DNS.LA | 第二批本地模拟验证通过；仅默认线路自动创建 |
| huaweicloud | 华为云 DNS | 第七批本地模拟验证通过；PUBLIC/ACTIVE/default_view 静态单值 RRset，显式区域/IAM 项目 |
| callback | 自定义回调 | 独立 JSON POST 能力本地验证通过；HTTP 接受/未验证，不读取 DNS、不宣称幂等更新、诊断零回调请求 |
| baiducloud | 百度云 DNS | 第七批本地模拟验证通过；仅 BCD 注册域名产品与显式 resource_id，不是通用 BCE DNS |
| porkbun | Porkbun | 第二批本地模拟验证通过 |
| godaddy | GoDaddy | 第三批本地模拟验证通过；只更新单值 RRset |
| namecheap | Namecheap | 第九批本地模拟/统一验证通过；all-active/plain BasicDNS 整区替换，明确 exclusive writer；保留邮件模式，逻辑 ID，完整读回；非任意区域/禁用/DDNS 元数据支持 |
| namesilo | NameSilo | 第六批本地模拟验证通过；原生 ID 每次更新轮换，使用稳定逻辑 ID |
| vercel | Vercel | 第三批本地模拟验证通过；只修改验证过的 Vercel DNS 区域 |
| dynadot | Dynadot | 暂缓；v2 非关键 Beta 候选，但删除匹配/同主机追加/单独子记录与 TTL/邮件保留未证明；通用 DELETE/body 和有限 casing 差异不是单独的普遍阻塞 |
| dynv6 | dynv6 | 第五批本地模拟验证通过；子记录、显式 provider-managed TTL，拒绝区域主地址/继承记录 |
| spaceship | Spaceship | 第五批本地模拟验证通过；自定义单值集合，非原子新增-验证-精确删除，部分失败需人工恢复 |
| nowcn | Now.cn | 待接入 |
| eranet | Eranet | 待接入 |
| tnethk | Tnet.hk | 待接入 |
| gcore | Gcore | 第五批本地模拟验证通过；单值静态 RRset/字符串备注，合成 ID；套餐由操作者声明 |
| edgeone | 腾讯云 EdgeOne | 第七批本地模拟验证通过；原生 TEODNS、NS/full 站点，不包含 OriginGroup 源站更新 |
| nsone | NS1 | 第三批本地模拟验证通过；仅静态单答案，无过滤器/区域/feeds/链接 |
| name_com | Name.com | 第四批本地模拟验证；当前 Core v1 API，整记录 PUT 前重读，保留 host/type/priority |
| rainyun | 雨云 | 第四批本地模拟验证；显式产品 ID，默认权威 NS，保留线路/level，拒绝暂停及产品绑定 |
| hipmdnsmgr | HiPM DNS Manager | 第六批本地模拟验证通过；自托管 HiDNS，仅支持审计过的 Aliyun 映射，端点由服务器环境变量控制 |
| cloudns | ClouDNS | 第四批本地模拟验证；普通 master 区域，TTL 按 API 读取，拒绝 GeoDNS/failover；区域状态响应兼容性待实账号确认 |
| desec | deSEC | 第二批本地模拟验证通过；多值 RRset 拒绝覆盖 |

## 剩余 5 项推进计划

暂缓项所需的官方澄清/既有脱敏离线样例见[契约证据清单](<docs/contract-fixtures.md>)。不要求在生产试写，不收集真实密钥。

更新日期：2026-11-09（Asia/Shanghai）。批次仅表示推进顺序，**不代表这些服务商已经可用**；每批均需真实接线、分页/状态/写操作语义核对、模拟回归及统一构建后才能改为已验证。

| 批次 | 服务商 | 当前状态 / 验收门槛 |
| --- | --- | --- |
| 第六批暂缓项 | Dynadot | v1 整区破坏风险仍不可回退；[v2 复审](<docs/dynadot-v2-second-opinion.md>)缩小过度泛化异议，仍需活动 DNS 库存、接受的 header、删除匹配、追加/TTL/邮件保留证据；不创建伪适配器 |
| 第八批暂缓项 | 阿里云 ESA | [窄 IPv4/unproxied 复审](<docs/aliesa-narrow-scope-review.md>)证明该候选可行，但普通记录快照/适用元数据保留合同尚不足；不要求非法回写只读字段，也不伪装为普通 AliDNS |
| 第九批剩余项 | Now.cn、Eranet、Tnet.hk | [官方 NowDNS 静态复审](<docs/nowdns-static-contract-review.md>)已确证第一方客户端签名/旧 base/case/原生字段，但其首数组读取、忽略 State/默认 TTL/弱回执不能照搬；仍需各品牌完整库存、状态保留与正回执合同 |

## 当前支持的凭据和限制

| kind | 凭据字段 | 环境变量前缀 | 说明 |
| --- | --- | --- | --- |
| tencentcloud | secret_id_env / secret_key_env | TENCENT_ | 腾讯云 SecretId/SecretKey；兼容旧配置缺省 kind |
| cloudflare | token_env | CLOUDFLARE_ | 限域 API Token；Zone Read + DNS Edit；不是 Global Key/email |
| alidns | secret_id_env / secret_key_env | ALIDNS_ | AccessKeyId / AccessKeySecret；区域可选 |
| dnspod | secret_id_env / secret_key_env | DNSPOD_ | 传统 Token ID / Token；仅主账号，不支持腾讯云 CAM 子账号 |
| porkbun | secret_id_env / secret_key_env | PORKBUN_ | API Key / Secret API Key；按 ID 更新，TTL 最低 600 秒的保守限制 |
| desec | token_env | DESEC_ | Token；专用单值 RRset，TTL 读取 domain.minimum_ttl |
| dnsla | secret_id_env / secret_key_env | DNSLA_ | API ID / API Secret；当前 HTTPS API，保留组/线路/权重 |
| godaddy | secret_id_env / secret_key_env | GODADDY_ | API Key / API Secret；单值 RRset，所有 404 均不被当作空记录 |
| vercel | token_env | VERCEL_ | Bearer Token；可选 team_id，使用官方当前 v5 完整记录列表 |
| nsone | token_env | NS1_ | NS1 API Key；唯一静态答案，拒绝过滤器、区域与数据源控制 |
| name_com | secret_id_env / secret_key_env | NAMECOM_ | 用户名 / API Token；当前 Core v1 Basic 认证，TTL 至少 300 |
| rainyun | token_env | RAINYUN_ | x-api-key；必填 options.domain_id，TTL 按官方客户端允许列表验证 |
| cloudns | secret_id_env / secret_key_env | CLOUDNS_ | API 用户 ID / API 密码；options.auth_type 可选 auth-id / sub-auth-id / sub-auth-user |
| dynv6 | token_env | DYNV6_ | REST HTTP Token；必填 ttl_mode=provider_default，配置 TTL 不生效；不修改区域主地址 |
| spaceship | secret_id_env / secret_key_env | SPACESHIP_ | API Key / Secret；domains:read、dnsrecords:read/write；自定义单值集合，非原子新增再删除 |
| gcore | token_env | GCORE_ | APIKey Token；可选真实套餐 plan；专用单值静态集合，仅支持空元数据或字符串备注 |
| namesilo | token_env | NAMESILO_ | 强制 GET 查询密钥认证；稳定逻辑 ID，原生 ID 每次写入轮换；基础 DNSOWL 单值记录 |
| hipmdnsmgr | token_env | HIPM_ | 自托管 HiDNS Bearer Token；必填 endpoint_env 为服务器 HIPM_ 引用，HTTPS；仅已审计 Aliyun 映射 |
| huaweicloud | secret_id_env / secret_key_env | HUAWEICLOUD_ | 永久 AK/SK；必填 region/project_id，可选 zone_id；default_view 单值 RRset，保守 TTL 最低 300 |
| baiducloud | secret_id_env / secret_key_env | BAIDUCLOUD_ | BCD AK/SK；必填 resource_id；原生正 int32 ID、实际线路；TTL 60–3600 |
| edgeone | secret_id_env / secret_key_env | EDGEONE_ | 腾讯云 SecretId/Key；必填 mode=dns/scope=teodns/api_version/zone_id；原生 TEODNS，需全部安全读取权限 |
| trafficroute | secret_id_env / secret_key_env | TRAFFICROUTE_ | 火山引擎 AccessKeyID/SecretAccessKey，不是腾讯云；public_dns/cn-beijing/2018-08-01/正 ZID；实际 TradeCode 限制 |
| callback | token_env | CALLBACK_ | 独立 Bearer JSON POST；端点仅服务器 CALLBACK_ 引用；必填未验证/每次执行/TTL 仅元数据确认，不能创建或读取 DNS |
| namecheap | secret_id_env / secret_key_env | NAMECHEAP_ | 账户 API User/Key，同一 UserName；scope/write_mode/environment/sld/tld/client_ip_env 必填；服务器白名单公网 IPv4 引用仅 NAMECHEAP_，不是目标 IP；整区唯一写入者 |

所有适配器的**凭据**也接受通用 `DDNS_` 环境变量命名空间。HiPM 的 `endpoint_env` 是单独的服务器端点授权范围，仅接受 `HIPM_`，不能使用 `DDNS_`、PATH 或字面 URL。服务端只读取受限引用，不返回实际密钥或 HiPM 端点值。

Cloudflare `ttl = 1` 表示自动；开启代理的记录必须使用自动 TTL。创建选项 `records.options.proxied` 只用于新增记录，更新保留实际代理状态。阿里云线路 `默认` 映射为 `default`。无线路概念的服务商忽略 `record_line`；有多条同名 A/AAAA 时仍拒绝盲选。

## 官方接口参考

- [Name.com 认证](https://docs.name.com/guides/authentication.md)、[当前 Core DNS 列表](https://docs.name.com/api/v1/reference/dns/list-records.md)、[整记录 PUT](https://docs.name.com/api/v1/reference/dns/update-record.md)、[域名读取](https://docs.name.com/api/v1/reference/domains/get-domain.md)
- [雨云域名产品详情](https://s.apifox.cn/a4595cc8-44c5-4678-a2a3-eed7738dab03/api-153559361.md)、[记录列表](https://s.apifox.cn/a4595cc8-44c5-4678-a2a3-eed7738dab03/api-153559362.md)、[创建](https://s.apifox.cn/a4595cc8-44c5-4678-a2a3-eed7738dab03/api-175421754.md)、[修改](https://s.apifox.cn/a4595cc8-44c5-4678-a2a3-eed7738dab03/api-175427268.md)。响应字段与保守 TTL 选项交叉核对官方 [域名客户端](https://app.rainyun.com/js/6487.1b3a89de.js) / [DNS 客户端](https://app.rainyun.com/js/8483.0009fb0b.js)，不是宣称服务端完整 schema 已发布。
- [ClouDNS API Help](https://www.cloudns.net/wiki/article/41/)、[区域信息](https://www.cloudns.net/wiki/article/134/)、[可用 TTL](https://www.cloudns.net/wiki/article/153/)、[官方 Go SDK 参数定义](https://raw.githubusercontent.com/ClouDNS/cloudns-go/main/api.go)、[创建 data.id 解析](https://raw.githubusercontent.com/ClouDNS/cloudns-go/main/cloudns.go)、[官方 OctoDNS 元数据保留测试](https://raw.githubusercontent.com/ClouDNS/octodns_cloudns/main/tests/test_live_metadata.py)

- [GoDaddy 当前域名 API schema](https://developer.godaddy.com/openapi/domains-v1.json)、[认证与资格](https://developer.godaddy.com/llms.mdx/api-users/auth)、[404 可隐藏不可见资源](https://developer.godaddy.com/llms.mdx/api-users/errors)
- [Vercel 当前 DNS 列表](https://vercel.com/docs/rest-api/dns/list-existing-dns-records.md)、[OpenAPI schema](https://openapi.vercel.sh)
- [NS1 官方 Python Record 资源](https://raw.githubusercontent.com/ns1/ns1-python/master/ns1/rest/records.py)、[Zone 资源](https://raw.githubusercontent.com/ns1/ns1-python/master/ns1/rest/zones.py)、[Go SDK 原始缺失记录消息](https://raw.githubusercontent.com/ns1/ns1-go/v2/rest/record.go)

- [Porkbun DNS API](https://porkbun.com/llms/dns)、[域名分页列表](https://porkbun.com/llms/domain)
- [deSEC RRsets](https://desec.readthedocs.io/en/latest/dns/rrsets.html)、[域名与 minimum_ttl](https://desec.readthedocs.io/en/latest/dns/domains.html)
- [DNS.LA 官方 API 文档](https://www.dns.la/docs/ApiDoc)（当前页面内嵌文档定义的接口，不使用旧版不安全 HTTP 地址）

- [Cloudflare zones](https://developers.cloudflare.com/api/resources/zones/methods/list/)、[DNS PATCH](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/edit/)、[TTL 限制](https://developers.cloudflare.com/dns/manage-dns-records/reference/ttl/)
- [AliDNS DescribeDomainRecords](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-describedomainrecords)、[UpdateDomainRecord](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-updatedomainrecord)
- [DNSPod 传统 API 公共参数](https://docs.dnspod.cn/api/api-public-request/)、[域名信息](https://docs.dnspod.cn/api/domain-info/)、[记录列表](https://docs.dnspod.cn/api/record-list/)、[修改记录](https://docs.dnspod.cn/api/modify-records/)、[创建记录](https://docs.dnspod.cn/api/add-record/)

## 后续接入约束

- `Adapter::validate_selection` 在 unchanged / would_update / would_create 之前执行；服务商专属 TTL、代理、RRset 或线路限制也必须在只读诊断中检出。
- `Record.line = ""` 仅表示服务商没有线路概念；有线路的 API 返回空默认线路时须规范化成明确的默认线路标识，不能把默认线路当作任意线路的通配符。
- `HttpReply.headers` 可供完整 Link/cursor 分页使用，但不能直接记录原始响应头；跟随下一页前校验 scheme/host/port/path，拒绝将认证发往外部链接。
- HTTP 204 的空响应会以 `Value::Null` 返回，由服务商按文档确认含义，不能泛化为成功（deSEC 的 204 表示删除）。
- 外部回调、服务商整区替换、单记录编辑与多值 RRset 是不同能力，不能混用。

不支持读取的“更新 URL”、整区替换型接口、多值 RRset 接口或有特殊路由/套餐限制的接口，必须分别设计能力限制，不能把通用单记录更新逻辑强行套上去。遇到单条记录更新可能删除同组其他值时，默认拒绝，或在明确可保留全部值的条件下实现读改写。
