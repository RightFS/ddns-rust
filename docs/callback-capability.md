# 独立回调能力：HTTP 接受，不是 DNS 验证

设计/本地回归日期：2026-11-09。是否已开放及最终验证数量以[全量进度](<../PROVIDERS.md>)为准。

## 与 DNS 适配器的区别

[回调实现](<../src/providers/callback.rs>)不实现 DNS `Adapter`，没有远端记录列表、原生 RecordId、既有 IP 比较、创建记录、TTL 控制或写后 DNS 读回。它也不是对上游任意 GET/模板回调的直接兼容。

初始范围仅为操作者显式确认的 **Bearer 认证 JSON POST** 接收器：

- `mode=json_post`
- `verification=unverified`
- `delivery=every_run`
- `ttl_mode=metadata_only`
- `endpoint_env` 为服务器 `CALLBACK_` 环境变量引用，不是 Web 中的实际 URL。

只有验证这些确认项和本地配置后才可执行。记录不能设置 `record_id`、`create_if_missing=true` 或自定义记录选项。线路没有回调含义。TTL 只是请求元数据，不代表已读取或设置远端 DNS。

## 接收器协议

每次真实执行都发送一次固定 JSON：

```json
{
  "domain": "home.example.com",
  "ip": "1.1.1.1",
  "record_type": "A",
  "ttl": 600,
  "delivery_id": "fresh-UUID-per-delivery"
}
```

`domain` 是配置区域与相对主机名组合的 FQDN；`ip` 是本次检测/指定的规范化 IP，而非远端观察值。每次生成新的 `delivery_id`，它只标识该次投递，**不保证接收器幂等性**。IP 未变也会再次投递。应用不自动重试，但后续调度和手工运行仍会再次发送，因此接收器须自行设计重复投递处理。

## 结果语义

| 状态 | 含义 |
| --- | --- |
| `would_call_unverified` | 本地选项/端点/元数据已验证；回调请求零发送，不证明接收器存在、鉴权成功或 DNS 可用 |
| `callback_accepted_unverified` | 完整、大小受限的 HTTP 2xx 响应；只证明 HTTP 接受，不证明业务成功或 DNS 更新 |
| `CallbackHttpRejected` | 非 2xx HTTP 回执；仅提供状态等安全元数据，不暴露任意响应体 |
| `DeliveryUncertain` | 传输中断、超时、响应不完整/过大等；接收器是否已处理、下游影响均未知，不自动重试 |

202、空 204、非 JSON 或含业务 `error` 的 2xx 都不能转换为“DNS 更新成功”。该协议没有通用业务回执定义，因此统一明确标识 **UNVERIFIED / 未验证**，不尝试猜测 JSON 成功字段。

## 端点与凭据

- Token 引用接受大写 `CALLBACK_` 或通用 `DDNS_` 命名空间，支持多账户；[示例](<../examples/callback.toml>)中的 `CALLBACK_TOKEN` 不是唯一允许的变量名。
- 端点引用只接受大写 `CALLBACK_` 范围（最多 64 字符、非空后缀）；不接受 `DDNS_`、PATH 或字面 URL。
- 实际端点由服务器环境提供，仅严格规范的 HTTPS URL。根路径 `/` 可用；拒绝 userinfo、查询参数、fragment、反斜杠、百分号转义、点段与模板。私有 HTTPS origin 仅作为受信任服务器操作者的显式选择允许。
- 保持 TLS 验证、禁用重定向与自动写重试。Bearer 头标记敏感；不输出实际端点、令牌、任意响应体/响应头或原始网络错误链。
- 响应最多 1 MiB，总投递/读取截止 30 秒。超过限制后不能假设请求没有产生下游效果。

## 本地证据

14 项 localhost/单元测试已通过，覆盖零回调 I/O 诊断、相同 IP 重复真实执行/不同 UUID、各种 2xx HTTP-only 语义、非 2xx、重定向接收目标零命中、响应大小/中断/超时不确定性、选项/端点/凭据和 IP 元数据校验。主工程 14 项回调测试已通过。最终配置/Web/目录与统一构建验收在[全量进度](<../PROVIDERS.md>)登记；这不是真实接收器或 DNS 传播验收。本轮未调用真实回调端点。
