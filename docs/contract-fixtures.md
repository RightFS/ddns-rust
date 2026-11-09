# 剩余接口：安全继续所需的离线契约证据

本清单针对尚未完成的 Dynadot、阿里云 ESA、Now.cn、Eranet、Tnet.hk；Namecheap 窄范围已实现，扩展能力的证据需求单独注明。**不是要求在生产环境试写 DNS**。优先采用官方澄清、公开 SDK 的真实请求/响应模型或既有的脱敏离线样例。

最终完成数量请见[全量进度](<../PROVIDERS.md>)。不因为缺少账号而创建永远不能更新的“已实现”适配器，也不将整区替换和单条记录修改混为一谈。

| 服务商 | 需要明确的关键证据 |
| --- | --- |
| Dynadot | 正常 DNS 模式 `get_dns` 的完整数据形状、数组/TTL/域名状态字段；接受的签名头、删除匹配/默认值、同主机共存、单独子记录 payload 与 TTL/邮件保留。命令专属 DELETE JSON 已有规范性依据，不再单独因通用无 body 指引暂缓；v2 Beta 需独立显式接受。 |
| 阿里云 ESA | 已有 IPv4-only、unproxied、原生 combined `A/AAAA` 候选，不需要先证明 IPv6-only 才能继续该窄范围；还需普通记录 Get/Update payload、适用字段合法保留或只读/派生属性证明，不要求非法 echo Tags/CustomPort，也不猜 BizName/Status 默认。 |
| Namecheap | all-active/plain BasicDNS 范围已由 [第一方 SDK 更新](<namecheap-sdk-contract-update.md>)支持并已完成本地实现/统一验证，不再以邮件模式省略保留/form POST/800 上限缺证据暂缓；若扩展到 inactive/DDNS/app metadata/CAA/ALIAS/重定向等仍需各自保留合同与离线样例。 |
| Now.cn | [当前 www/lowercase 文档 getter 的独立前端证据](<registrar-state-contract-review.md>)绑定 state=0 正常、2 暂停，并暴露分页键；还需该签名认证上下文的原始 Data/Pagination envelope、完整计数/页规则、TTL/线路/诊断 remark 分类和 GET 更新保留/回执，不把 legacy api.now.cn/capital-Dns 自动等同。 |
| Eranet | 同样已有本品牌当前文档 getter 的 state=0/2、MX/线路/分页客户端证据；还需 HMAC 上下文的完整原始响应与 GET 合法保留/回执，不能把 POST 前端省略 State/Remark 当作服务器不变保证。 |
| Tnet.hk | 同样已有本品牌当前 www getter 的正常/暂停和 MX/线路/分页证据；还需独立签名上下文的实际 schema、完整库存和 GET 更新保留/回执，不推定 State=1 活动，也不借用集团响应。 |

详细差异见 [Dynadot](<dynadot-contract-notes.md>)、[ESA](<aliesa-contract-notes.md>)、[ESA 窄范围复审](<aliesa-narrow-scope-review.md>)与[注册商审查](<registrar-contract-notes.md>)。[官方 NowDNS 静态复审](<nowdns-static-contract-review.md>)已确证第一方客户端采用 AccessInstanceID、secret + `&`、Now 旧 base/case 及每 ID 更新字段；这些不是实测服务端接收或完整库存证明。其客户端会忽略 State、把零 TTL 默认为 600、只消费一页 Data、没有正更新回执核对，不能照搬。继续需要各品牌原生 State 语义/保留、完整库存及回执样例，不再把未公开 PHP 本身作为签名线索缺失。公开 Todaynic 经销商示例也不能自动证明三个独立域名接口具有相同分页。

## 样例如何脱敏

- 移除 Authorization、Cookie、Token、密码、AK/SK、API 用户、签名及带鉴权查询的完整 URL；不要提供账户配置中的底层凭据。
- 域名可统一替换为 `example.com`、`home.example.com` 等；IP 使用文档地址 `192.0.2.1`、`2001:db8::1`。替换须保持区域/相对名/FQDN 的关系一致，不能把相对名误改为 FQDN。
- ID 可一致映射为占位 ID，但保留原始 JSON 类型（数字还是字符串），并保留更新前/回执/更新后是否相同、是否轮换的关系。
- 保留字段是否存在、null/空值/数组/对象/布尔的区别，真实 TTL/线路/权重/活动状态的语义和分页计数。不要为了“精简”删除未知控制字段；不能从字段缺失推定安全默认值。
- 对签名测试优先提供官方公开测试向量及虚构测试密钥，**不提供真实密钥**。
- 请求/响应必须标注 API 名称、版本、所属产品和 HTTP 状态；不要把 Dynamic DNS 更新 URL 的回执当作权威库存样例。

收到证据后，下一步是补充本地模拟回归、完整快照/身份核对、仅支持可证明的窄能力、重新构建与更新目录状态。没有真实账号时，完成标准仍是本地模拟验证，不宣称线上账号或 DNS 传播验收。
