# 剩余五项：可直接使用的离线证据请求

当前已完成 24/29 项本地接线验证；此文件帮助补齐剩余接口契约，**不是要求提供凭据、登录账户或在生产试写 DNS**。已有的脱敏捕获、公开第一方规范、明确的服务商说明均可。只提供其中一家的一组可证明窄范围的材料，也能继续该家，不必一次补齐五家。

## 不需要额外证明什么

- 不要求原子 CAS、全部套餐/记录类型、线上传播验收或一定存在官方 SDK。
- 不要求回写 GET-only 字段；证明字段只读/派生/不适用即可，也可以采用明确的省略保留合同。
- 不强制回执包含原生 ID；已定义的成功/错误语义加严格读回可能足够，但 HTTP 2xx 本身不等于 DNS 成功。
- 不把 State=1 当作活动默认。三家当前文档 www/lowercase getter 已有 **0 正常、2 暂停**的第一方前端绑定；需要明确其适用认证/产品上下文。
- Dynadot 命令专属 DELETE JSON 已有规范性依据。ALL-family singleton owner 可显著消除同名多记录/无用 value2 匹配问题；明确接受非关键中断风险的 delete-before-add 也可绕过共存要求。仍需可验证完整状态和合法局部修改，不能因此默认整区替换安全。

## 每家的最小下一步

| 服务商 | 足以推动一个窄范围的下一组证据 |
| --- | --- |
| ESA | 普通 **unproxied、单 IPv4、原生 A/AAAA** Get/Create/Update 字段合同或既有脱敏序列；说明适用字段的合法写回/省略保留，以及 Tags/CustomPort 等是派生、只读、不适用还是有实际作用。无需先支持 IPv6-only、代理端口或其它 RR 类型；不猜 BizName=dns、Status=enabled、零值/空对象重置语义。 |
| Dynadot | 活动且可确认完整的 DNS-mode getter：原生字段、实际 TTL、数组/计数/上限与适用全局设置；加一份该范围合法 set_dns payload/保留说明。可限定无邮件/转发/广告等设置和单记录 owner，但须证明该无设置状态，不能把字段缺失当作空值。选择 append 或明确 opt-in 的 interrupted delete/add 方案；v1 整区替换不得作为回退。签名按一个已支持规范固定，不双头试探/自动重试。 |
| Now.cn | 当前明确 origin/path/case 的独立 HMAC getter 原始 Data/Pagination，或明确其与已绑定 State=0 的当前文档 getter 的关系；验证所有页/总数/上限和原始 domain/host/state/TTL/MX/line/remark。再给该范围的 **GET** per-ID payload/保留说明及已定义回执/读回。可限定正常、默认线路、无用户/诊断备注的现有 A/AAAA，不必任意 settings。 |
| Eranet | 与上项同类，但明确来自本品牌/其支持的独立 API。当前同站前端 POST 转发 Mx/Ttl/Line 和省略 State/Remark 是有用线索，不自行证明 GET 省略不变。 |
| Tnet.hk | 同类本品牌证据；说明 native/auth-context 与当前 www/lowercase getter 的状态/页协议关系。不要从同集团或相同前端代码推导所有签名接口的响应必定相同。 |

## 材料标识模板（不是 API 响应样例）

以下仅描述材料来源，尖括号必须替换；它不是合格的 DNS 数据、不应加入正向 mock：

```text
provider: <esa | dynadot | nowcn | eranet | tnethk>
product_and_version: <实际产品/API 版本>
evidence_kind: <公开规范 | 第一方客户端意图 | 已有脱敏实际捕获>
source_url_or_revision: <可追溯 URL、revision，或说明捕获来源>
auth_context: <独立 API HMAC | portal session | 其它已支持方式>
origin_path_method: <精确 HTTPS origin、path/case、method，不含鉴权 query>
operation: <完整读取 | 窄范围合法更新 | 回执 | 更新后读取>
http_status: <真实 HTTP 状态，仅实际捕获填写>
files: <相应原始结构文件及用途>
redaction_changes: <只改变哪些域名/IP/ID，哪些字段类型/关系保持>
known_guarantees_and_unknowns: <不得把猜测写成已观察保证>
```

每个响应保留原有外层 envelope、字段存在/缺失、null/空字符串/空数组/对象的区别和类型。ID 一致映射但保留数字/字符串及轮换关系；域名替换时保留相对名/FQDN/区域关系；保留所有控制字段、实际 TTL、线路、MX、状态和真实分页数。不要补齐未知字段、合成 HostCount/total，也不要把 UI export 当作未过滤的原始库存。

移除 Authorization/Cookie/Token/API 用户或密钥/签名/含鉴权 query 的 URL；不提供真实密码或环境变量值。签名向量只用公开的虚构测试材料。更新前后材料仅接受已有或服务商提供的序列；**不要求新发生产写入、清空区域、启用/暂停记录、发送回调或执行 SDK 验收套件**。

## 收到材料后的处理

先核对产品、认证与 namespace，确定哪些字段是适用控制、只读/派生或未知；再验证完整库存、状态和实际合法 payload。只实现可证明的窄范围，补 localhost 回归、未变动字段读回、安全错误/重试策略、Config/API/Web 接线和构建，最后才更新 implemented 计数。来源不足的 synthetic mock 可以测试故障拒绝，但不能补出服务商合同。

详见[全量进度](<../PROVIDERS.md>)、[脱敏清单](<contract-fixtures.md>)、[ESA 窄范围复审](<aliesa-narrow-scope-review.md>)、[Dynadot 第二意见](<dynadot-v2-second-opinion.md>)和[三家当前状态/分页证据](<registrar-state-contract-review.md>)。
