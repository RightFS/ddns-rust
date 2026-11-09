/* ddns-rust admin: dependency-free, cookie sessions and write-only credential drafts. */
'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const words = {
    zh: {
      console:'运维控制台',fields:'个字段',workspace:'工作空间',overview:'诊断概览',configuration:'配置管理',logs:'运行日志',localControl:'安全的本地控制',securityNote:'凭据由服务端环境变量提供。此页面只处理脱敏配置。',language:'语言',headline:'先诊断，再更新。',subtitle:'检查 IP 来源、DNS 记录与服务状态，让每一次更新都有据可查。',refresh:'刷新数据',authTitle:'连接到服务',tokenHelp:'输入 Bearer Token。仅在当前标签页的 sessionStorage 中保存，不会写入 URL。',token:'访问令牌',connect:'连接',disconnect:'断开',serviceState:'执行状态',connectFirst:'连接后获取真实状态',recordCount:'启用记录',lastRun:'最近执行',noRun:'尚无执行报告',polling:'自动刷新',seconds:'秒',authenticatedOnly:'仅在认证后启用',troubleshooting:'故障排查优先',diagnoseTitle:'先验证整个更新链路',diagnoseHelp:'只读诊断检查所有记录（包括禁用记录）的 IP 来源与 DNS 状态，不创建、不修改 DNS。操作使用已保存的服务端配置。',nonModifying:'DRY RUN · 不修改 DNS',diagnose:'运行只读诊断',manualUpdate:'手动更新 DNS',export:'导出诊断 JSON ↓',recordStatus:'记录状态',reportHelp:'真实执行结果与完整故障信息会显示在这里。',waiting:'等待数据',noReport:'暂无执行报告',noReportHelp:'连接服务后运行只读诊断，开始排查。',configHelp:'友好的表单，持久化到配置文件。这里只填写环境变量名称，不填写密钥。',notLoaded:'未加载',interval:'更新间隔（秒）',timeout:'请求超时（秒）',configLogLevel:'配置日志级别',providers:'DNS 提供商',addProvider:'＋ 添加提供商',providerHelp:'在服务端设置 TENCENT_ 开头的大写环境变量（如 TENCENT_SECRET_ID）。只填写变量名，不填写密钥。',records:'DNS 记录',addRecord:'＋ 添加记录',advanced:'高级：完整 JSON 配置编辑器',jsonHelp:'打开时同步当前表单。编辑 JSON 后点击“应用到表单”，再保存。只接受脱敏配置字段。',applyJson:'应用到表单',saveHelp:'修改不会自动保存。保存后，启用的记录会在下一更新周期自动更新 DNS；建议保持禁用并先运行只读诊断。',reloadConfig:'重新加载',saveConfig:'保存配置',logHelp:'服务端日志原文保留英文。筛选与搜索每 5 秒刷新。',runtimeLevel:'动态日志级别',searchPlaceholder:'搜索日志消息与字段…',levelFilter:'级别筛选',allLevels:'所有级别',noLogs:'暂无日志。连接服务后加载。',noMatchingLogs:'没有符合筛选条件的日志。',footer:'可观测、可验证的动态 DNS',exportHelp:'导出不含访问令牌；分享前请检查域名、IP 与日志。',confirmTitle:'确认真实更新 DNS？',confirmHelp:'此操作将使用已保存的配置，可能创建或修改启用的 DNS 记录。建议先运行只读诊断。',cancel:'取消',confirmUpdate:'确认并更新',connected:'已连接',disconnected:'未连接',connecting:'连接中…',idle:'空闲',running:'执行中',dryRun:'只读诊断',realRun:'真实更新',saved:'已保存',unsaved:'未保存',providerName:'提供商名称',secretIdEnv:'Secret ID 环境变量',secretKeyEnv:'Secret Key 环境变量',remove:'移除',recordName:'记录名称',provider:'提供商',domain:'主域名',subdomain:'子域名',recordType:'记录类型',recordLine:'解析线路',ttl:'TTL（秒）',recordId:'记录 ID（可选）',enabled:'启用记录',createMissing:'不存在时创建',ipKind:'IP 来源',ipValue:'来源值',url:'URL 获取',static:'静态 IP',interface:'网络接口',urlHelp:'返回 IP 的 HTTP(S) URL',staticHelp:'IPv4 或 IPv6 地址',interfaceHelp:'服务端网络接口名称，例如 eth0',chooseProvider:'选择提供商',emptyProviders:'尚未配置提供商。添加提供商并引用服务端环境变量。',emptyRecords:'尚未配置记录。添加 A 或 AAAA 记录。',stage:'阶段',code:'错误码',message:'错误信息',hint:'修复建议',requestId:'RequestId',httpStatus:'HTTP 状态',retryable:'可重试',yes:'是',no:'否',outcome:'结果详情',raw:'完整结果 JSON',ip:'IP 地址',status:'状态',unknown:'未知',failed:'失败',success:'成功',updated:'已更新',unchanged:'无需更新',created:'已创建',skipped:'已跳过',disabled:'已禁用',would_update:'将更新',would_create:'将创建',ok:'正常',error:'错误',validated:'已验证',busy:'已有任务正在执行，请等待完成后再试。',authError:'认证失败，请检查访问令牌。',networkError:'请求失败，请检查网络与服务状态。',connectedNotice:'连接成功。配置、状态与日志已开始加载。',savedNotice:'配置已验证并保存。启用的记录会在下一更新周期自动更新 DNS；禁用记录仍可运行只读诊断。',jsonApplied:'JSON 已应用到表单，请保存以持久化。',invalidConfig:'配置格式无效，请检查字段与 JSON。',unsavedConfirm:'存在未保存的修改。重新加载将丢弃这些修改，继续？',jsonPending:'JSON 编辑尚未应用，请先点击“应用到表单”。',runStarted:'任务已提交。',runDone:'执行已完成，请查看记录结果。',levelSet:'动态日志级别已更新（仅运行时；持久化请另存配置）。',refreshed:'最后刷新',providerTotal:'个提供商',recordsTotal:'条记录',storageWarning:'浏览器存储不可用；令牌仅在内存中使用。',logsTotal:'条日志',apiFailure:'API 请求失败',missingToken:'请输入访问令牌。',loading:'处理中…',finished:'已完成',inProgress:'进行中',configRequired:'请先加载配置。',invalidNumber:'请输入有效的正整数。',unknownField:'不允许的配置字段',duplicate:'名称必须唯一',required:'必填项不能为空',invalidSource:'IP 来源必须是 url、static 或 interface',invalidBoolean:'布尔字段必须为 true 或 false'
    },
    en: {
      console:'Operations console',fields:'fields',workspace:'WORKSPACE',overview:'Diagnostics',configuration:'Configuration',logs:'Activity logs',localControl:'Secure local control',securityNote:'Credentials come from server environment variables. This page only handles sanitized configuration.',language:'Language',headline:'Diagnose first. Update confidently.',subtitle:'Inspect IP sources, DNS records and service health. Make every update traceable.',refresh:'Refresh',authTitle:'Connect to your service',tokenHelp:'Enter a Bearer token. Saved only in this tab’s sessionStorage, never in the URL.',token:'Access token',connect:'Connect',disconnect:'Disconnect',serviceState:'Execution state',connectFirst:'Connect to load live state',recordCount:'Enabled records',lastRun:'Last execution',noRun:'No execution report yet',polling:'Auto-refresh',seconds:'s',authenticatedOnly:'Active only after authentication',troubleshooting:'TROUBLESHOOTING FIRST',diagnoseTitle:'Verify the entire update pipeline',diagnoseHelp:'Read-only diagnostics check IP sources and DNS state for all records, including disabled ones. No DNS changes. Actions use saved server configuration.',nonModifying:'DRY RUN · NO DNS CHANGES',diagnose:'Run read-only diagnostics',manualUpdate:'Update DNS manually',export:'Export diagnostic JSON ↓',recordStatus:'Record status',reportHelp:'Actual execution results and complete error details appear here.',waiting:'Awaiting data',noReport:'No execution report',noReportHelp:'Connect and run read-only diagnostics to begin troubleshooting.',configHelp:'Friendly forms, persisted to your configuration file. Enter environment variable names, never secret values.',notLoaded:'Not loaded',interval:'Update interval (seconds)',timeout:'Request timeout (seconds)',configLogLevel:'Configured log level',providers:'DNS providers',addProvider:'＋ Add provider',providerHelp:'Use uppercase server environment names starting with TENCENT_ (e.g. TENCENT_SECRET_ID). Enter names, never secret values.',records:'DNS records',addRecord:'＋ Add record',advanced:'Advanced: full JSON configuration editor',jsonHelp:'Opening synchronizes the current form. Apply edited JSON to the form, then save. Only sanitized configuration fields are accepted.',applyJson:'Apply to form',saveHelp:'Edits are not auto-saved. Saved enabled records will update DNS at the next interval. Keep new records disabled and diagnose first.',reloadConfig:'Reload',saveConfig:'Save configuration',logHelp:'Server log messages remain in English. Filters and search refresh every 5 seconds.',runtimeLevel:'Runtime log level',searchPlaceholder:'Search log messages and fields…',levelFilter:'Level filter',allLevels:'All levels',noLogs:'No logs yet. Connect to load logs.',noMatchingLogs:'No logs match the current filters.',footer:'Observable, verifiable dynamic DNS',exportHelp:'Exports exclude your token. Review domains, IPs and logs before sharing.',confirmTitle:'Confirm a real DNS update?',confirmHelp:'This uses saved configuration and may create or modify enabled DNS records. Run read-only diagnostics first if unsure.',cancel:'Cancel',confirmUpdate:'Confirm & update',connected:'Connected',disconnected:'Disconnected',connecting:'Connecting…',idle:'Idle',running:'Running',dryRun:'Read-only diagnostics',realRun:'Real update',saved:'Saved',unsaved:'Unsaved changes',providerName:'Provider name',secretIdEnv:'Secret ID environment variable',secretKeyEnv:'Secret key environment variable',remove:'Remove',recordName:'Record name',provider:'Provider',domain:'Domain',subdomain:'Subdomain',recordType:'Record type',recordLine:'Record line',ttl:'TTL (seconds)',recordId:'Record ID (optional)',enabled:'Enabled',createMissing:'Create if missing',ipKind:'IP source',ipValue:'Source value',url:'Fetch from URL',static:'Static IP',interface:'Network interface',urlHelp:'HTTP(S) URL that returns an IP',staticHelp:'IPv4 or IPv6 address',interfaceHelp:'Server interface name, e.g. eth0',chooseProvider:'Select provider',emptyProviders:'No providers configured. Add one using server environment variable names.',emptyRecords:'No records configured. Add an A or AAAA record.',stage:'Stage',code:'Error code',message:'Message',hint:'Suggested fix',requestId:'RequestId',httpStatus:'HTTP status',retryable:'Retryable',yes:'Yes',no:'No',outcome:'Outcome details',raw:'Full result JSON',ip:'IP address',status:'Status',unknown:'Unknown',failed:'Failed',success:'Success',updated:'Updated',unchanged:'Unchanged',created:'Created',skipped:'Skipped',disabled:'Disabled',would_update:'Would update',would_create:'Would create',ok:'OK',error:'Error',validated:'Validated',busy:'Another task is running. Wait for it to finish and try again.',authError:'Authentication failed. Check your access token.',networkError:'Request failed. Check your network and service.',connectedNotice:'Connected. Loading configuration, status and logs.',savedNotice:'Configuration validated and saved. Enabled records update DNS at the next interval; disabled records can still be diagnosed read-only.',jsonApplied:'JSON applied to the form. Save to persist it.',invalidConfig:'Invalid configuration. Check the fields and JSON.',unsavedConfirm:'You have unsaved changes. Reloading will discard them. Continue?',jsonPending:'JSON edits have not been applied. Click “Apply to form” first.',runStarted:'Execution submitted.',runDone:'Execution finished. Review the record results.',levelSet:'Runtime log level updated (runtime only; save configuration separately to persist).',refreshed:'Last refresh',providerTotal:'providers',recordsTotal:'records',storageWarning:'Browser storage unavailable; the token is held only in memory.',logsTotal:'logs',apiFailure:'API request failed',missingToken:'Enter an access token.',loading:'Working…',finished:'Finished',inProgress:'In progress',configRequired:'Load configuration first.',invalidNumber:'Enter a valid positive integer.',unknownField:'Unsupported configuration field',duplicate:'Names must be unique',required:'Required fields cannot be empty',invalidSource:'IP source must be url, static or interface',invalidBoolean:'Boolean fields must be true or false'
    }
  };
  Object.assign(words.zh, {providerHelp:'按提供商填写服务端环境变量名称；接受该提供商前缀或通用 DDNS_ 前缀。绝不要填写密钥值。',providerKind:'提供商类型',tokenEnv:'API Token 环境变量',providerOptions:'提供商选项',recordOptions:'记录选项',zoneId:'Zone ID（可选）',region:'区域（可选）',proxied:'Cloudflare 代理',unset:'未指定',true:'true（启用）',false:'false（禁用）',pendingProviders:'上游目录中尚未实现（不可选择）',invalidRegistry:'提供商目录接口不可用或格式无效；请升级服务端',unsupportedProvider:'该提供商尚未实现或不在服务端目录中',invalidEnv:'无效的环境变量名称：必须是大写字母、数字、下划线，并使用提供商前缀或 DDNS_ 前缀',invalidRecordId:'记录 ID 必须为 1–128 位字母、数字、_、. 或 -，且不能为 0',switchDraft:'仅修改本地草稿：已清除不适用的凭据、选项或记录 ID。保存前不会更改服务端或 DNS。',localDraftHelp:'类型或记录提供商切换仅修改本地草稿，会清除不适用字段和记录 ID；只有保存才发送配置。',credentialHelp:'只填写环境变量名称，不填写实际密钥值。允许前缀：',aliLineHelp:'阿里云：记录线路“默认”由服务端映射为 default。',recordIdHelp:'可选的不透明文本 ID（最多 128 字符）；留空自动查找。'});
  Object.assign(words.en, {providerHelp:'Enter server environment variable names with the provider prefix or generic DDNS_ prefix. Never enter secret values.',providerKind:'Provider type',tokenEnv:'API Token environment variable',providerOptions:'Provider options',recordOptions:'Record options',zoneId:'Zone ID (optional)',region:'Region (optional)',proxied:'Cloudflare proxy',unset:'Not specified',true:'true (enabled)',false:'false (disabled)',pendingProviders:'Upstream catalog: not implemented (not selectable)',invalidRegistry:'Provider registry unavailable or invalid; upgrade the server',unsupportedProvider:'Provider is unimplemented or missing from the server registry',invalidEnv:'Invalid environment variable name: use uppercase letters, digits and underscores with the provider prefix or DDNS_ prefix',invalidRecordId:'Record ID must be 1–128 letters, digits, _, . or -, and cannot be 0',switchDraft:'Local draft only: incompatible credentials, options or record IDs were cleared. No server or DNS changes until Save.',localDraftHelp:'Changing type or a record’s provider edits only the local draft and clears incompatible fields and record IDs; configuration is sent only on Save.',credentialHelp:'Enter the environment variable name, never the actual secret value. Allowed prefixes: ',aliLineHelp:'AliDNS: the server maps the record line “默认” to default.',recordIdHelp:'Optional opaque text ID (up to 128 characters); leave empty for lookup.'});
  Object.assign(words.zh,{credentialIdEnv:'凭据 ID 环境变量',credentialKeyEnv:'凭据密钥环境变量',accessIdEnv:'AccessKey ID 环境变量',accessKeyEnv:'AccessKey Secret 环境变量',dnspodIdEnv:'DNSPod ID 环境变量',dnspodTokenEnv:'DNSPod Token 环境变量',proxyHelp:'仅创建新记录时设置代理状态；现有记录的代理状态保持不变。',numericRecordIdHelp:'腾讯云、阿里云及旧版 DNSPod 要求正十进制 ID（不超过 u64）；仍以文本保存，避免精度丢失。'});
  Object.assign(words.en,{credentialIdEnv:'Credential ID environment variable',credentialKeyEnv:'Credential key environment variable',accessIdEnv:'AccessKey ID environment variable',accessKeyEnv:'AccessKey Secret environment variable',dnspodIdEnv:'DNSPod ID environment variable',dnspodTokenEnv:'DNSPod Token environment variable',proxyHelp:'Proxy setting applies only to new records; existing records retain their proxy state.',numericRecordIdHelp:'Tencent Cloud, AliDNS and legacy DNSPod require a positive decimal ID (up to u64); it is kept as text to avoid precision loss.'});
  Object.assign(words.zh,{porkbunApiKeyEnv:'Porkbun API Key 环境变量',porkbunSecretKeyEnv:'Porkbun Secret API Key 环境变量',dnslaApiIdEnv:'DNS.LA API ID 环境变量',dnslaApiSecretEnv:'DNS.LA API Secret 环境变量'});
  Object.assign(words.en,{porkbunApiKeyEnv:'Porkbun API Key environment variable',porkbunSecretKeyEnv:'Porkbun Secret API Key environment variable',dnslaApiIdEnv:'DNS.LA API ID environment variable',dnslaApiSecretEnv:'DNS.LA API Secret environment variable'});
  Object.assign(words.zh,{godaddyApiKeyEnv:'GoDaddy API Key 环境变量',godaddyApiSecretEnv:'GoDaddy API Secret 环境变量',teamId:'团队 ID（可选）'});
  Object.assign(words.en,{godaddyApiKeyEnv:'GoDaddy API Key environment variable',godaddyApiSecretEnv:'GoDaddy API Secret environment variable',teamId:'Team ID (optional)'});
  Object.assign(words.zh,{namecomUsernameEnv:'Name.com 用户名环境变量',namecomTokenEnv:'Name.com API Token 环境变量',cloudnsIdEnv:'ClouDNS API 用户 ID / 子用户环境变量',cloudnsPasswordEnv:'ClouDNS API 密码环境变量',rainyunTokenEnv:'雨云 API Key 环境变量',domainProductId:'雨云域名产品 ID（必填）',cloudnsAuthType:'ClouDNS 认证方式（可选）'});
  Object.assign(words.en,{namecomUsernameEnv:'Name.com username environment variable',namecomTokenEnv:'Name.com API Token environment variable',cloudnsIdEnv:'ClouDNS API user ID / sub-user environment variable',cloudnsPasswordEnv:'ClouDNS API password environment variable',rainyunTokenEnv:'Rainyun API Key environment variable',domainProductId:'Rainyun domain product ID (required)',cloudnsAuthType:'ClouDNS authentication type (optional)'});
  Object.assign(words.zh,{ttlMode:'TTL 模式（必填 provider_default）',providerManagedTtl:'服务商管理 TTL：dynv6 REST 不提供 TTL 读写，配置 TTL 不生效；不会为 TTL 差异写入。仅支持显式子记录，不支持 @。',spaceshipApiKeyEnv:'Spaceship API Key 环境变量',spaceshipApiSecretEnv:'Spaceship API Secret 环境变量',spaceshipSafetyHelp:'仅支持自定义单值记录集。地址更新先新增验证再删除旧值；非原子操作，失败时可能保留双值，需人工检查。建议更新周期至少 300 秒。'});
  Object.assign(words.en,{ttlMode:'TTL mode (required provider_default)',providerManagedTtl:'Provider-managed TTL: dynv6 REST does not read/write TTL. Configured TTL is ignored; TTL differences cause no writes. Explicit child records only, no @.',spaceshipApiKeyEnv:'Spaceship API Key environment variable',spaceshipApiSecretEnv:'Spaceship API Secret environment variable',spaceshipSafetyHelp:'Custom singleton RRsets only. Address changes add and verify before deleting the old value. Non-atomic failures may leave both values; inspect manually. Use an interval of at least 300 seconds.'});
  Object.assign(words.zh,{actualPlan:'真实套餐（可选 free/pro/enterprise）',gcoreSafetyHelp:'仅支持单值、启用的静态记录集及备注元数据；拒绝路由、健康检查或 CDN 控制。最低 TTL：Free 120 / Pro 30 / Enterprise 1 秒。套餐由操作者声明，API 不独立验证账户套餐。'});
  Object.assign(words.en,{actualPlan:'Actual plan (optional free/pro/enterprise)',gcoreSafetyHelp:'Only enabled static singleton RRsets and notes metadata. Routing, health checks and CDN controls are refused. Minimum TTL: Free 120 / Pro 30 / Enterprise 1 seconds. The operator declares the plan; the API does not independently verify account entitlement.'});
  Object.assign(words.zh,{namesiloTokenEnv:'NameSilo API Key 环境变量',hipmTokenEnv:'HiPM API Token 环境变量',endpointEnv:'服务端 endpoint 环境变量（必填）',managerDomainId:'管理器域名 ID（可选）',endpointEnvHelp:'只填写 HIPM_ 开头的 6–64 位大写环境变量名（不接受 DDNS_、PATH 或 URL）。服务端变量保存经 TLS 验证的 HTTPS origin，可含 /api；私有 origin 仅可由服务端显式配置。页面不会读取或返回实际 URL，不支持不安全 TLS。',nativeLineHelp:'HiPM：必须填写实际原生 Aliyun ASCII 线路代码，例如 default；不猜测映射 默认。切换现有记录后请手动核对原生代码。仅支持已审计的 aliyun 账户；更新省略 status/weight/remark 以保持现状，不信任响应中的 URL。',namesiloSafetyHelp:'NameSilo 官方 API 必须通过 GET key 查询参数传递密钥；请避免代理、访问日志和请求 URL 泄露密钥。原生记录 ID 每次写入都会轮换；保存 namesilo-hash 逻辑 ID 以稳定定位。'});
  Object.assign(words.en,{namesiloTokenEnv:'NameSilo API Key environment variable',hipmTokenEnv:'HiPM API Token environment variable',endpointEnv:'Server endpoint environment name (required)',managerDomainId:'Manager domain ID (optional)',endpointEnvHelp:'Enter only a 6–64-character uppercase HIPM_ environment name (no DDNS_, PATH or URL). The server variable holds a TLS-verified HTTPS origin, optionally /api; a private origin must be explicitly configured on the server. The page never reads or returns the actual URL; insecure TLS is not supported.',nativeLineHelp:'HiPM requires the actual native Aliyun ASCII line code, e.g. default; no mapping from 默认 is guessed. After switching an existing record, manually verify the native code. Only audited aliyun accounts are supported; writes omit status/weight/remark to preserve them, and response URLs are not trusted.',namesiloSafetyHelp:'The official NameSilo API requires the key in a GET query parameter; avoid key exposure in proxy/access logs and request URLs. Native record IDs rotate on every write; persist the stable namesilo-hash logical ID.'});
  Object.assign(words.zh,{huaweiRegion:'华为云 DNS 区域（必填）',projectId:'区域 IAM 项目 ID（必填）',resourceId:'已注册域名 resourceId（必填）',dnsMode:'模式（必填 dns）',dnsScope:'范围（必填 teodns）',apiVersion:'API 版本（必填 2022-09-01）',nativeZoneId:'原生 Zone ID（zone-...）',huaweiSafetyHelp:'仅支持 PUBLIC、ACTIVE 区域中的 default_view、静态单值、weight=1 A/AAAA 记录集。region/project_id 是不可变可信端点上下文，不做项目发现或端点覆盖。提供商与记录 zone_id 必须一致；原生 ID 不接受 . / .. 或 URL。最低 TTL 300 是保守上线限制，不声称账户最低值。异步写入可能返回 WritePending；先人工核实，不自动重试。无条件写入接口，必须单一写入者。',baiduSafetyHelp:'仅支持精确已注册域名的 resource_id，不猜测托管子域；通过服务商配置的 nameserver 证明，不声称实时公网委派验证。原生 BCD 使用相对名称（允许 home.nested），单条 A/AAAA；原生记录 ID 为正 int32 十进制。线路 DEFAULT/CMNET/CNC/EDU/SEARCH，default/默认 精确映射 DEFAULT。TTL 60–3600；无账户最低 TTL 查询。写后读取确认，无自动重试，必须单一写入者。',edgeoneSafetyHelp:'仅支持 NS 接入的 full 站点原生 TEODNS，绝非 Origin/源站组，也不回退 DNSPod。必填 mode=dns、scope=teodns、api_version=2022-09-01、zone_id=zone-...；record_id=record-...。默认线路 Default（default/默认 别名）；其他线路必须为实际原生 Location。TTL 60–86400。必须授予四个读 API：DescribeZones、DescribeDnsRecords、DescribeAccelerationDomains、旧版 DescribeApplicationProxies；最后一个安全检查失败时关闭操作，不降级跳过。写入还需 ModifyDnsRecords / 可选 CreateDnsRecord 权限。不接受 endpoint/group/region 覆盖；必须单一写入者。'});
  Object.assign(words.en,{huaweiRegion:'Huawei DNS region (required)',projectId:'Regional IAM project ID (required)',resourceId:'Registered-domain resourceId (required)',dnsMode:'Mode (required dns)',dnsScope:'Scope (required teodns)',apiVersion:'API version (required 2022-09-01)',nativeZoneId:'Native Zone ID (zone-...)',huaweiSafetyHelp:'PUBLIC ACTIVE zones only: default_view, static singleton weight-1 A/AAAA RRsets. Immutable region/project_id define the trusted endpoint context; no project discovery or endpoint override. Provider/record zone_id must agree; native IDs reject . / .. and URL syntax. Minimum TTL 300 is a conservative rollout limit, not a claimed account minimum. Async writes may return WritePending; inspect manually before retrying. No conditional writes: use one writer.',baiduSafetyHelp:'Exact registered-domain resource_id only; no hosted-child-zone guessing. Nameserver proof checks provider configuration, not live public delegation. Native BCD uses RELATIVE names (home.nested is valid), single A/AAAA records and positive int32 decimal native IDs. Lines DEFAULT/CMNET/CNC/EDU/SEARCH; default/默认 map exactly to DEFAULT. TTL 60–3600; no account minimum-TTL discovery. Writes require readback; no automatic retry, use one writer.',edgeoneSafetyHelp:'NS/full sites only, native TEODNS NOT Origin or origin groups; no DNSPod fallback. Require mode=dns, scope=teodns, api_version=2022-09-01, zone_id=zone-... and native record_id=record-.... Default line (default/默认 aliases); other lines must be exact native Location. TTL 60–86400. All four read APIs are required: DescribeZones, DescribeDnsRecords, DescribeAccelerationDomains and legacy DescribeApplicationProxies; this safety check fails closed, never skips or falls back. Writes also need ModifyDnsRecords / optional CreateDnsRecord permission. No endpoint/group/region overrides. Use one writer.'});
  Object.assign(words.zh,{volcIdEnv:'火山引擎 AccessKeyID 环境变量',volcKeyEnv:'火山引擎 SecretAccessKey 环境变量',trafficScope:'范围（必填 public_dns）',trafficVersion:'API 版本（必填 2018-08-01）',trafficRegion:'签名区域（必填 cn-beijing）',trafficZone:'火山引擎 ZID（正 int64）',trafficSafetyHelp:'火山引擎 Volcengine TrafficRoute，不是腾讯云 DNSPod。仅支持既有公共权威 DNS 区域 public_dns，Stage 0 读取 ListZones/QueryZone/ListRecords/ListRecordSets/ListLines/QueryRecord；通过服务商 NS 配置证明，不声称实时公网委派验证。完整分页与 RRset/LB 检查，仅静态单值、非加权记录集；拒绝 GTMLockTags。默认线路 default（仅 default/默认/空值别名），其他须为真实原生 Value，不猜测枚举。TTL 1–86400，真实账户套餐最低 TTL 由 ListLines 读取，不猜测。固定 dns.volcengineapi.com、2018-08-01、cn-beijing；必须单一写入者。',callbackSafetyHelp:'UNVERIFIED · 独立非 DNS 回调能力：HTTP 2xx（包括 202 或业务错误正文）仅表示接受请求，绝不是 DNS 更新成功。没有 DNS 读取、远端 IP 证明或记录创建。每次真实运行均发送全新 delivery_id UUID，不承诺幂等，不自动重试。接收端必须支持固定 JSON POST 协议：domain（FQDN）、ip、record_type、ttl（仅元数据）、delivery_id。禁用并先诊断；dry run 零回调网络 IO。',callbackEndpointHelp:'仅填写 CALLBACK_ 开头、6–64 位大写且后缀非空的服务端环境变量名，不接受 DDNS_/PATH/URL。实际 URL 仅由可信服务端变量设置：规范 HTTPS 路径（允许根路径），无查询、用户信息、片段、百分号、反斜线、点路径或模板。私有 HTTPS 仅服务端信任配置；无不安全 TLS、重定向或 GET 模板。页面不读取或返回实际 URL。',callbackIgnoredHelp:'回调忽略记录线路与 DNS TTL 控制。TTL 仅为 JSON 声明元数据，不会读取/修改远端 DNS；记录 ID 和缺失创建不可用。',callback_accepted_unverified:'回调已接受 · UNVERIFIED（未验证 DNS）',would_call_unverified:'将发送回调 · UNVERIFIED（零投递）',verification:'验证声明（必填 unverified）',delivery:'投递声明（必填 every_run）',callbackMode:'模式（必填 json_post）',callbackTtl:'TTL 声明（必填 metadata_only）'});
  Object.assign(words.en,{volcIdEnv:'Volcengine AccessKeyID environment variable',volcKeyEnv:'Volcengine SecretAccessKey environment variable',trafficScope:'Scope (required public_dns)',trafficVersion:'API version (required 2018-08-01)',trafficRegion:'Signing region (required cn-beijing)',trafficZone:'Volcengine ZID (positive int64)',trafficSafetyHelp:'Volcengine TrafficRoute, NOT Tencent DNSPod. Existing public authoritative DNS zones only: public_dns. Stage 0 reads ListZones/QueryZone/ListRecords/ListRecordSets/ListLines/QueryRecord; provider NS configuration proof is not live public delegation proof. Full pagination and RRset/LB inspection: static singleton non-weighted RRsets only; GTMLockTags refused. Native default (exact default/默认/empty aliases); other lines require actual native Value, no guessed enum. TTL 1–86400; actual account edition minimum is read via ListLines, never guessed. Fixed dns.volcengineapi.com, 2018-08-01, cn-beijing. Require one writer.',callbackSafetyHelp:'UNVERIFIED · Independent NON-DNS callback capability: HTTP 2xx (including 202 or business-error bodies) only acknowledges acceptance, NEVER DNS success. No DNS read, remote IP proof or record creation. Every real run sends a fresh delivery_id UUID; no idempotency guarantee or automatic retry. Receiver must implement fixed JSON POST: domain (FQDN), ip, record_type, ttl (metadata only), delivery_id. Keep disabled and diagnose first; dry run performs zero callback network I/O.',callbackEndpointHelp:'Only a 6–64-character uppercase CALLBACK_ server environment reference with nonempty suffix, never DDNS_/PATH/URL. Trusted server environment alone sets the actual URL: canonical HTTPS path (root allowed), no query/userinfo/fragment/percent/backslash/dot segments/templates. Private HTTPS is server-trusted only; no insecure TLS, redirects or GET templates. The page never reads or returns the actual URL.',callbackIgnoredHelp:'Callback ignores record line and DNS TTL control. TTL is declared JSON metadata only; no remote DNS read/write. Record ID and create-if-missing are unavailable.',callback_accepted_unverified:'Callback accepted · UNVERIFIED (not DNS success)',would_call_unverified:'Would call · UNVERIFIED (no delivery)',verification:'Verification (required unverified)',delivery:'Delivery (required every_run)',callbackMode:'Mode (required json_post)',callbackTtl:'TTL acknowledgement (required metadata_only)'});
  Object.assign(words.zh,{diagnoseHelp:'诊断所有记录（包括禁用记录）的 IP 来源与 DNS 状态，不修改 DNS。独立回调只做本地预检，零投递；报告 IP 是期望值，绝非远端 DNS 证明。',manualUpdate:'手动执行 DNS / 回调',confirmTitle:'确认真实执行 DNS / 回调？',confirmHelp:'将使用已保存配置，可能修改启用的 DNS 记录。每条启用回调每次执行均再次投递：UNVERIFIED，HTTP 接受不是 DNS 成功，不承诺幂等。先诊断；不确定投递请检查接收端，勿盲目重复。',saveHelp:'修改不会自动保存。保存后启用记录将在下一周期执行；回调每次均再次投递且 UNVERIFIED。建议保持禁用并先诊断。'});
  Object.assign(words.en,{diagnoseHelp:'Check IP sources and DNS state for all records, including disabled ones; no DNS changes. Independent callbacks perform local preflight only, zero delivery. Report IP is the desired value, NOT remote DNS proof.',manualUpdate:'Run DNS / callbacks manually',confirmTitle:'Confirm real DNS / callback execution?',confirmHelp:'Uses saved configuration and may modify enabled DNS records. Every enabled callback sends again each run: UNVERIFIED, HTTP acceptance is not DNS success, no idempotency guarantee. Diagnose first; inspect the receiver before repeating uncertain delivery.',saveHelp:'Changes are not saved automatically. Enabled records execute next cycle after Save; callbacks send again every run and remain UNVERIFIED. Keep disabled and diagnose first.'});
  Object.assign(words.zh,{namecheapUserEnv:'Namecheap 账户 API 用户名环境变量',namecheapKeyEnv:'Namecheap 账户 API Key 环境变量',namecheapScope:'范围（必填 basicdns_plain）',namecheapWriteMode:'整区写入确认（必填 exclusive_full_zone）',namecheapEnvironment:'账户环境（必填 production / sandbox）',namecheapSld:'显式 SLD（必填，如 example）',namecheapTld:'显式 TLD（必填，如 com / co.uk）',namecheapClientIpEnv:'服务端出口 IPv4 环境变量名（必填 NAMECHEAP_）',namecheapIdHelp:'可选稳定逻辑 ID：namecheap- 后接 64 位小写十六进制 SHA256；由后端精确验证域名/相对名称/类型范围。原生 HostId 仅为诊断元数据，不是配置 ID。',namecheapSafetyHelp:'Namecheap 账户 API 用户名/API Key，不是域名 Dynamic DNS 密码或 GET 更新 URL。APIUser=UserName，仅初始自有账户；表单 POST，XML 响应。必填 scope=basicdns_plain、write_mode=exclusive_full_zone：明确同意替换整区全部 host 行，不是单记录写入或 CAS；必须单一独占写入者。显式 sld/tld，domain 必须等于 sld.tld，不猜 PSL。client_ip_env 仅 NAMECHEAP_ 服务端环境引用，实际白名单公网 IPv4 是服务端出口 IP，不是 DDNS 目标 IP；不返回或保存实际值。仅已注册自有未过期 BasicDNS，所有行启用且无 DDNS/故障切换/应用/友好名称元数据；A/AAAA/TXT/CNAME/NS/MX（MX 仅 MX 邮件模式）。整区最多 800 行；可选 HostCount 与数组不符即拒绝。规范 TTL 60–60000/MXPref，非 MX 初始限制 MXPref=10；拒绝 CAA/ALIAS/SRV/重定向等未知类型。省略 EmailType 保持 OX/FWD/GMAIL 等隐藏邮件模式，不重建邮件。稳定逻辑 ID，原生 HostId 可轮换。缺失创建支持显式选择，但须完整整区缺失证明，默认禁用。完整新鲜读取、一次整区写入、全部行与设置读回；不确定失败先人工恢复核查，不自动重试；竞态仍可能发生。nameserver 证明仅 API 配置，不声称 DNS 传播或在线账户验收。'});
  Object.assign(words.en,{namecheapUserEnv:'Namecheap account API username environment variable',namecheapKeyEnv:'Namecheap account API Key environment variable',namecheapScope:'Scope (required basicdns_plain)',namecheapWriteMode:'Whole-zone acknowledgement (required exclusive_full_zone)',namecheapEnvironment:'Account environment (required production / sandbox)',namecheapSld:'Explicit SLD (required, e.g. example)',namecheapTld:'Explicit TLD (required, e.g. com / co.uk)',namecheapClientIpEnv:'Server egress IPv4 environment name (required NAMECHEAP_)',namecheapIdHelp:'Optional stable logical ID: namecheap- plus 64 lowercase hexadecimal SHA256 characters. Backend verifies exact domain/relative-owner/type scope. Native HostId is diagnostic metadata, NOT a configuration ID.',namecheapSafetyHelp:'Namecheap account API username/API Key, NOT the domain Dynamic DNS password or GET update URL. APIUser=UserName, initial owned account only; form POST with XML response. Require scope=basicdns_plain and write_mode=exclusive_full_zone: explicitly acknowledge replacement of ALL zone host rows, NOT per-record writes or CAS; require one exclusive writer. Explicit sld/tld: domain must equal sld.tld, no PSL guessing. client_ip_env is a NAMECHEAP_-only server reference: actual whitelisted public IPv4 is server egress, NOT the DDNS target IP; actual value is never returned or stored. Owned registered nonexpired BasicDNS only; EVERY row active, no DDNS/failover/app/friendly metadata. A/AAAA/TXT/CNAME/NS/MX only (MX rows require MX mail mode). Whole inventory max 800; optional HostCount mismatch fails closed. Canonical TTL 60–60000/MXPref; initial non-MX restriction MXPref=10. CAA/ALIAS/SRV/redirect and unknown types refused. Omit EmailType to preserve hidden OX/FWD/GMAIL mail state, never reconstruct mail. Stable logical ID; native HostId may rotate. Create-if-missing opt-in is supported only with whole-zone absence proof; keep disabled by default. Fresh complete reads, one whole-zone replacement, full settings/multiset readback; inspect uncertain failures and recovery manually, no automatic retry. Races remain possible. Nameserver proof is API configuration only, NOT DNS propagation or online account acceptance.'});
  Object.assign(words.zh,{authLoading:'正在检查账户…',retry:'重试',setupTitle:'创建管理员账户',setupHelp:'首次使用：创建账户即可开始，无需环境变量或访问令牌。密码须为 8–128 UTF-8 字节。',loginTitle:'登录控制台',loginHelp:'使用用户名和密码登录。会话保存在安全的 HttpOnly Cookie 中。',username:'用户名',password:'密码',confirmPassword:'确认密码',setup:'创建账户',login:'登录',logout:'退出登录',legacyToken:'高级：旧版 Bearer Token',invalidUsername:'用户名去除首尾空格后须为 1–64 UTF-8 字节',invalidPassword:'密码须为 8–128 UTF-8 字节',passwordMismatch:'两次输入的密码不一致',settings:'服务设置',settingsHelp:'监听地址修改在重启后生效；用户名、密码或令牌修改会注销所有会话，需要重新登录。',listen:'监听地址',activeListen:'当前监听地址（只读）',newPassword:'新密码（留空不修改）',newToken:'旧版令牌（留空可禁用）',changeToken:'修改 / 禁用旧版令牌',saveSettings:'保存设置',settingsSaved:'设置已保存',restartRequired:'监听地址变更将在重启后生效',loginRequired:'账户或令牌已修改，请重新登录',configured:'已配置；留空保留，编辑为空清除',notConfigured:'未配置',directCredentials:'直接凭据（只写）',directEndpoint:'直接 HTTPS 端点（只写）',directClientIp:'服务端出口 IPv4（只写）',advancedRefs:'高级：环境变量引用（兼容旧配置）',directHelp:'可以直接输入凭据，或使用服务端环境变量。已保存值不会返回；编辑为空可清除。JSON 与诊断导出只含脱敏标记。',securityNote:'账户使用 Cookie 会话；凭据只写入服务端，页面不会读取已保存的密钥。',configHelp:'友好的表单，持久化到配置文件。支持直接凭据或环境变量引用；已保存凭据只显示脱敏标记。',providerHelp:'直接填写凭据即可使用；也可在高级选项中引用提供商前缀或 DDNS_ 环境变量。',jsonHelp:'仅同步脱敏配置，绝不包含表单中的凭据草稿。直接凭据请使用表单，不要粘贴到 JSON。',rawSecretJson:'JSON 仅接受凭据脱敏标记；请在凭据表单填写实际值。'});
  Object.assign(words.en,{authLoading:'Checking account…',retry:'Retry',setupTitle:'Create your administrator account',setupHelp:'First run: create an account to begin. No environment variables or access token required. Password: 8–128 UTF-8 bytes.',loginTitle:'Sign in to your console',loginHelp:'Sign in with your username and password. Sessions use an HttpOnly cookie.',username:'Username',password:'Password',confirmPassword:'Confirm password',setup:'Create account',login:'Sign in',logout:'Sign out',legacyToken:'Advanced: legacy Bearer token',invalidUsername:'Trimmed username must be 1–64 UTF-8 bytes',invalidPassword:'Password must be 8–128 UTF-8 bytes',passwordMismatch:'Passwords do not match',settings:'Service settings',settingsHelp:'Listen changes apply after restart. Username, password or token changes invalidate all sessions and require sign-in.',listen:'Listen address',activeListen:'Active listen address (read-only)',newPassword:'New password (leave blank to keep)',newToken:'Legacy token (blank can disable)',changeToken:'Change / disable legacy token',saveSettings:'Save settings',settingsSaved:'Settings saved',restartRequired:'Listen change applies after restart',loginRequired:'Account or token changed; sign in again',configured:'Configured; blank preserves, editing to empty clears',notConfigured:'Not configured',directCredentials:'Direct credentials (write-only)',directEndpoint:'Direct HTTPS endpoint (write-only)',directClientIp:'Server egress IPv4 (write-only)',advancedRefs:'Advanced: environment references (legacy compatible)',directHelp:'Enter credentials directly or use server environment references. Saved values are never returned; edit to empty to clear. JSON and diagnostic export contain redacted markers only.',securityNote:'Accounts use cookie sessions. Credentials are written to the server; stored secrets are never read back.',configHelp:'Friendly forms persisted to your configuration file. Use direct credentials or environment references; stored values are redacted.',providerHelp:'Enter credentials directly, or use provider-prefixed / DDNS_ environment references under Advanced.',jsonHelp:'Only redacted configuration is synced, never credential drafts. Use the credential form rather than pasting secrets into JSON.',rawSecretJson:'JSON accepts credential redaction markers only; enter actual values in the credential form.'});
  const storage = { get(store,key) { try { return window[store].getItem(key); } catch (_) { return null; } }, set(store,key,value) { try { window[store].setItem(key,value); return true; } catch (_) { return false; } }, remove(store,key) { try { window[store].removeItem(key); } catch (_) {} } };
  let locale = storage.get('localStorage','ddns.locale') === 'en' ? 'en' : 'zh';
  const t = key => words[locale][key] || key;
  Object.assign(words.zh, {
    chooseInterface:'选择网卡', interfaceMissing:'当前列表中找不到', interfaceUnavailable:'无法读取服务端网卡，请重新加载配置。',
    noInterfaces:'服务端没有可列出的网卡。', noInterfaceAddresses:'此网卡没有该协议的地址。',
    interfaceRegex:'IP 正则过滤（可选）', invalidInterfaceRegex:'IP 正则必须是字符串，且仅适用于网卡来源。',
    interfaceRegexHelp:'只更新匹配正则的公网地址。留空时匹配所有公网地址。多个匹配时，按 IP 数值升序取第一个。',
    interfacePreview:'匹配结果', interfacePreviewSelected:'将使用', interfacePreviewEmpty:'没有匹配的公网地址。',
    interfacePreviewError:'正则表达式有误。', interfacePreviewUnavailable:'无法加载匹配结果。',
    credentialId:'凭据 ID', credentialSecret:'凭据 Secret', credentialToken:'API 令牌'
  });
  Object.assign(words.en, {
    chooseInterface:'Select network interface', interfaceMissing:'Missing from current list', interfaceUnavailable:'Could not load server interfaces. Reload the configuration to try again.',
    noInterfaces:'No server interfaces were found.', noInterfaceAddresses:'This interface has no addresses for this family.',
    interfaceRegex:'IP regex filter (optional)', invalidInterfaceRegex:'The IP regex must be a string and is only supported for interface sources.',
    interfaceRegexHelp:'Only matching public addresses can be published. Leave blank to match all public addresses. If several match, the first in ascending numeric IP order is used.',
    interfacePreview:'Matches', interfacePreviewSelected:'Selected for update', interfacePreviewEmpty:'No matching public addresses.',
    interfacePreviewError:'Invalid regular expression.', interfacePreviewUnavailable:'Could not load matching addresses.',
    credentialId:'Credential ID', credentialSecret:'Credential Secret', credentialToken:'API token'
  });
  const state = { token:storage.get('sessionStorage','ddns.token') || '',authenticated:false,connecting:false,authMode:'loading',initialized:null,settings:null,settingsPending:false,config:null,registry:[],interfaces:null,status:null,logs:[],dirty:false,jsonDirty:false,runPending:false,saving:false,levelPending:false,refreshing:false,logsPending:false,epoch:0,lastRefresh:null };
  let pollTimer = null, searchTimer = null;
  const CONFIGURED='__DDNS_CONFIGURED__';
  const byteLength=value=>new TextEncoder().encode(value).length;
  let credentialDrafts=new WeakMap();
  const text = (id,value) => { $(id).textContent = value; };
  function node(tag,className,value) { const n=document.createElement(tag); if(className)n.className=className; if(value !== undefined)n.textContent=String(value); return n; }
  function notice(message,kind='info') { const n=$('notice'); n.textContent=message; n.className=`notice ${kind}`; n.hidden=!message; }
  function date(value) { if(!value)return '—'; const d=new Date(value); return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString(locale==='zh'?'zh-CN':'en-US'); }
  function json(value) { return JSON.stringify(value,null,2); }
  function updateControls() {
    document.querySelectorAll('[data-auth]').forEach(n=>{ n.disabled=!state.authenticated; });
    $('configFields').disabled=!state.authenticated || !state.config || state.saving;
    renderAuth();
    $('connect').disabled=state.connecting || state.authenticated || state.authMode==='loading';
    $('connect').textContent=t(state.connecting?'connecting':state.authMode==='setup'?'setup':'login');
    $('settingsFields').disabled=!state.authenticated || !state.settings || state.settingsPending;
    $('reloadSettings').disabled=!state.authenticated || state.settingsPending;
    $('disconnect').hidden=!state.authenticated;
    for(const id of ['token','username','password','confirmPassword','tokenConnect'])$(id).disabled=state.connecting || state.authenticated;
    $('refresh').disabled=!state.authenticated || state.refreshing;
    $('saveConfig').disabled=!state.authenticated || !state.config || state.saving || state.runPending || !!state.status?.running;
    $('saveConfig').textContent=t(state.saving?'loading':'saveConfig');
    $('reloadConfig').disabled=!state.authenticated || state.saving;
    const busy=state.runPending || !!state.status?.running || state.saving;
    $('diagnose').disabled=!state.authenticated || busy;
    $('run').disabled=!state.authenticated || busy;
    $('runtimeLevel').disabled=!state.authenticated || state.levelPending;
    text('connectionState',t(state.connecting?'connecting':state.authenticated?'connected':'disconnected'));
    $('connectionState').classList.toggle('connected',state.authenticated);
    text('dirtyState',t(!state.config?'notLoaded':state.dirty || state.jsonDirty?'unsaved':'saved'));
    $('dirtyState').className=`badge ${state.dirty || state.jsonDirty?'warning':'neutral'}`;
  }
  function translate() {
    document.documentElement.lang=locale==='zh'?'zh-CN':'en'; document.title=`ddns-rust · ${t('console')}`; $('locale').value=locale;
    document.querySelectorAll('[data-i18n]').forEach(n=>n.textContent=t(n.dataset.i18n));
    document.querySelectorAll('[data-i18n-placeholder]').forEach(n=>n.placeholder=t(n.dataset.i18nPlaceholder));
    if(state.config) renderConfig(); renderStatus(); renderLogs(); updateControls();
  }
  function renderAuth() {
    const loading=state.authMode==='loading',setup=state.authMode==='setup';
    text('authTitle',t(loading?'authLoading':setup?'setupTitle':'loginTitle'));
    text('authHelp',state.authenticated?t('connected'):t(setup?'setupHelp':'loginHelp'));
    $('authLoading').hidden=!loading;$('authRetry').hidden=state.authMode!=='error';
    $('authForm').hidden=state.authenticated || !['setup','login'].includes(state.authMode);
    $('legacyAuth').hidden=state.authenticated || state.authMode!=='login';
    $('confirmPasswordLabel').hidden=!setup;$('confirmPassword').required=setup;
    $('password').minLength=1;$('password').autocomplete=setup?'new-password':'current-password';
  }
  function validateAccount(username,password,confirm,setup=true) {
    username=username.trim();if(!username || byteLength(username)>64)throw new Error(t('invalidUsername'));
    if(setup && (byteLength(password)<8 || byteLength(password)>128) || !password || byteLength(password)>128)throw new Error(t('invalidPassword'));
    if(setup && password!==confirm)throw new Error(t('passwordMismatch'));
    return {username,password};
  }
  function maskedConfig(c) {const copy=JSON.parse(json(c));for(const p of copy.providers || [])if(p.credentials)for(const key of Object.keys(p.credentials))if(p.credentials[key])p.credentials[key]=CONFIGURED;return copy;}
  function configPayload(c) {const copy=JSON.parse(json(c));c.providers.forEach((p,i)=>{const draft=credentialDrafts.get(p);if(draft)copy.providers[i].credentials={...(copy.providers[i].credentials || {}),...draft};});return copy;}
  function wipePasswords(direct=true) {for(const id of ['password','confirmPassword','settingsPassword','settingsToken'])$(id).value='';if(direct){document.querySelectorAll('[data-direct-credential]').forEach(input=>input.value='');credentialDrafts=new WeakMap();}}
  function markDirty() { state.dirty=true; updateControls(); }
  function checkKeys(value,allowed) { if(!value || typeof value!=='object' || Array.isArray(value))throw new Error(t('invalidConfig')); for(const key of Object.keys(value))if(!allowed.includes(key))throw new Error(`${t('unknownField')}: ${key}`); }
  const positive = v => Number.isSafeInteger(v) && v>0;
  const credentialKeys=['secret_id_env','secret_key_env','token_env'];
  const descriptor = kind => state.registry.find(p=>p.kind===kind && p.implemented);
  const recordDescriptor = r => descriptor(state.config?.providers.find(p=>p.name===r.provider)?.kind);
  const providerLabel = d => locale==='zh'?({tencentcloud:'腾讯云 DNSPod',cloudflare:'Cloudflare',alidns:'阿里云 DNS',dnspod:'DNSPod 旧版 API',porkbun:'Porkbun',dnsla:'DNS.LA',desec:'deSEC',godaddy:'GoDaddy',vercel:'Vercel',nsone:'NS1',name_com:'Name.com',rainyun:'雨云',cloudns:'ClouDNS',dynv6:'dynv6',spaceship:'Spaceship',gcore:'Gcore',namesilo:'NameSilo',hipmdnsmgr:'HiPM DNS 管理器',huaweicloud:'华为云 DNS',baiducloud:'百度云 BCD DNS',edgeone:'腾讯云 EdgeOne TEODNS',trafficroute:'火山引擎 TrafficRoute DNS',callback:'独立回调 · UNVERIFIED'})[d.kind] || d.label:d.label;
  const credentialLabel = (kind,f) => {
    if(f.key==='token_env')return ({rainyun:'rainyunTokenEnv',namesilo:'namesiloTokenEnv',hipmdnsmgr:'hipmTokenEnv'})[kind] || 'tokenEnv';
    const labels={namecheap:['namecheapUserEnv','namecheapKeyEnv'],trafficroute:['volcIdEnv','volcKeyEnv'],spaceship:['spaceshipApiKeyEnv','spaceshipApiSecretEnv'],name_com:['namecomUsernameEnv','namecomTokenEnv'],cloudns:['cloudnsIdEnv','cloudnsPasswordEnv'],tencentcloud:['secretIdEnv','secretKeyEnv'],alidns:['accessIdEnv','accessKeyEnv'],dnspod:['dnspodIdEnv','dnspodTokenEnv'],porkbun:['porkbunApiKeyEnv','porkbunSecretKeyEnv'],dnsla:['dnslaApiIdEnv','dnslaApiSecretEnv'],godaddy:['godaddyApiKeyEnv','godaddyApiSecretEnv']};
    return (labels[kind] || ['credentialIdEnv','credentialKeyEnv'])[f.key==='secret_id_env'?0:1];
  };
  const optionLabel = d => ({zone_id:'zoneId',region:'region',project_id:'projectId',resource_id:'resourceId',mode:'dnsMode',scope:'dnsScope',api_version:'apiVersion',proxied:'proxied',team_id:'teamId',endpoint_env:'endpointEnv',domain_id:'domainProductId',auth_type:'cloudnsAuthType',ttl_mode:'ttlMode',plan:'actualPlan'})[d.key] || d.label || d.key;
  function validateRegistry(registry) {
    if(!Array.isArray(registry))throw new Error(t('invalidRegistry'));
    const kinds=new Set();
    registry.forEach(p=>{
      if(!p || typeof p.kind!=='string' || !p.kind || kinds.has(p.kind) || typeof p.label!=='string' || typeof p.implemented!=='boolean')throw new Error(t('invalidRegistry'));
      if(p.supports_dns_read!==undefined && typeof p.supports_dns_read!=='boolean')throw new Error(t('invalidRegistry'));
      kinds.add(p.kind);
      for(const key of ['credential_fields','options','record_options']) {
        if(!Array.isArray(p[key]))throw new Error(t('invalidRegistry'));
        const keys=new Set();p[key].forEach(d=>{if(!d || typeof d.key!=='string' || !d.key || keys.has(d.key) || typeof d.label!=='string' || typeof d.required!=='boolean' || (key==='credential_fields' && (!credentialKeys.includes(d.key) || typeof d.env_prefix!=='string' || !/^[A-Z][A-Z0-9_]*_$/.test(d.env_prefix))))throw new Error(t('invalidRegistry'));keys.add(d.key);});
      }
    });
    if(!registry.some(p=>p.implemented))throw new Error(t('invalidRegistry'));return registry;
  }
  function validateOptions(options,descriptors) {
    checkKeys(options,descriptors.map(d=>d.key));
    for(const [key,value] of Object.entries(options))if(typeof value!=='string')throw new Error(`${key}: ${t('invalidConfig')}`);
    descriptors.forEach(d=>{if(!d.required && options[d.key]==='')delete options[d.key];if(d.required && !options[d.key]?.trim())throw new Error(`${d.key}: ${t('required')}`);});
    if(options.plan!==undefined && !['free','pro','enterprise'].includes(options.plan))throw new Error('plan: free / pro / enterprise');
    if(options.ttl_mode!==undefined && !['provider_default','metadata_only'].includes(options.ttl_mode))throw new Error('ttl_mode: provider_default');
    if(options.proxied!==undefined && !['true','false'].includes(options.proxied))throw new Error(`proxied: true / false`);
  }
  const hasAliyunrouting = kind => ['tencentcloud','alidns','dnspod','dnsla','rainyun','hipmdnsmgr'].includes(kind);
  const huaweiRegions=['cn-east-2','cn-east-3','cn-north-1','cn-north-4','cn-south-1','cn-southwest-2','af-south-1','ap-southeast-1','ap-southeast-2','ap-southeast-3','sa-brazil-1','la-south-2','la-north-2','na-mexico-1','cn-north-9','cn-north-2','cn-south-2','ap-southeast-4','ae-ad-1','ru-moscow-1','me-east-1','ap-southeast-5','cn-east-5','cn-east-4','tr-west-1','af-north-1','my-kualalumpur-1'];
  const pathId=v=>typeof v==='string' && /^[A-Za-z0-9_.-]{1,128}$/.test(v) && !['0','.','..'].includes(v);
  const batchHelp={namecheap:'namecheapSafetyHelp',huaweicloud:'huaweiSafetyHelp',baiducloud:'baiduSafetyHelp',edgeone:'edgeoneSafetyHelp',trafficroute:'trafficSafetyHelp',callback:'callbackSafetyHelp'};
  const targetLine=(kind,line)=>kind==='trafficroute'?(['','default','默认'].includes(line)?'default':line):kind==='baiducloud'?(['default','默认'].includes(line)?'DEFAULT':line):kind==='edgeone'?(['default','默认'].includes(line)?'Default':line):hasAliyunrouting(kind)?(line==='默认'||line.toLowerCase()==='default'?'default':line):'';
  function validateConfig(c) {
    checkKeys(c,['interval_secs','timeout_secs','log_level','providers','records']);
    if(!positive(c.interval_secs)||!positive(c.timeout_secs))throw new Error(t('invalidNumber'));
    if(!['trace','debug','info','warn','error'].includes(c.log_level)||!Array.isArray(c.providers)||!Array.isArray(c.records))throw new Error(t('invalidConfig'));
    const requireStrings=(o,keys)=>keys.forEach(k=>{if(typeof o[k]!=='string'||!o[k].trim())throw new Error(`${k}: ${t('required')}`);});
    const names=new Set(); c.providers.forEach(p=>{
      checkKeys(p,['name','kind',...credentialKeys,'options','credentials']);requireStrings(p,['name']);
      if(p.kind===undefined)p.kind='tencentcloud';if(p.options===undefined)p.options={};
      credentialKeys.forEach(key=>{if(p[key]===undefined)p[key]='';if(typeof p[key]!=='string')throw new Error(`${key}: ${t('invalidConfig')}`);});
      const d=descriptor(p.kind);if(!d)throw new Error(`${p.kind}: ${t('unsupportedProvider')}`);
      if(p.credentials!==undefined){checkKeys(p.credentials,[...d.credential_fields.map(f=>f.key),...d.options.filter(f=>['endpoint_env','client_ip_env'].includes(f.key)).map(f=>f.key)]);for(const value of Object.values(p.credentials))if(typeof value!=='string')throw new Error(t('invalidConfig'));}
      const direct=key=>!!p.credentials?.[key];
      for(const key of credentialKeys){const f=d.credential_fields.find(f=>f.key===key);const value=p[key];if(f?.required && !value && !direct(key))throw new Error(`${key}: ${t('required')}`);if(value && (value.length>128 || !f || !/^[A-Z][A-Z0-9_]*$/.test(value) || !(value.startsWith(f.env_prefix) && value.length>f.env_prefix.length || value.startsWith('DDNS_') && value.length>5)))throw new Error(`${key}: ${t('invalidEnv')} (${f?.env_prefix || '—'} / DDNS_)`);}
      validateOptions(p.options,d.options.map(f=>direct(f.key)?{...f,required:false}:f));
      if(p.kind==='namecheap') {
        const dns=v=>typeof v==='string' && v.length>0 && v.length<=253 && v.split('.').every(l=>l.length>0 && l.length<=63 && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(l));
        if(p.options.scope!=='basicdns_plain' || p.options.write_mode!=='exclusive_full_zone' || !['production','sandbox'].includes(p.options.environment) || !dns(p.options.sld) || p.options.sld.includes('.') || !dns(p.options.tld) || p.options.tld.length>10 || `${p.options.sld}.${p.options.tld}`.length>253 || (!direct('client_ip_env') && !p.options.client_ip_env || p.options.client_ip_env && (!/^NAMECHEAP_[A-Z0-9_]+$/.test(p.options.client_ip_env) || p.options.client_ip_env.length>64)))throw new Error(t('namecheapSafetyHelp'));
      }
      if(p.kind==='dynv6'  && p.options.ttl_mode!=='provider_default')throw new Error(t('providerManagedTtl'));
      if(p.kind==='trafficroute' && (p.options.scope!=='public_dns' || p.options.api_version!=='2018-08-01' || p.options.region!=='cn-beijing' || !/^[1-9][0-9]*$/.test(p.options.zone_id) || BigInt(p.options.zone_id)>9223372036854775807n))throw new Error(t('trafficSafetyHelp'));
      if(p.kind==='callback' && ((!direct('endpoint_env') && !p.options.endpoint_env || p.options.endpoint_env && (!/^CALLBACK_[A-Z0-9_]+$/.test(p.options.endpoint_env) || p.options.endpoint_env.length>64)) || p.options.mode!=='json_post' || p.options.verification!=='unverified' || p.options.delivery!=='every_run' || p.options.ttl_mode!=='metadata_only'))throw new Error(t('callbackEndpointHelp')+' '+t('callbackSafetyHelp'));
      if(p.kind==='huaweicloud' && (!huaweiRegions.includes(p.options.region) || !pathId(p.options.project_id) || p.options.zone_id!==undefined && !pathId(p.options.zone_id)))throw new Error(t('huaweiSafetyHelp'));
      if(p.kind==='baiducloud' && !pathId(p.options.resource_id))throw new Error(t('baiduSafetyHelp'));
      if(p.kind==='edgeone' && (p.options.mode!=='dns' || p.options.scope!=='teodns' || p.options.api_version!=='2022-09-01' || !pathId(p.options.zone_id) || !p.options.zone_id.startsWith('zone-')))throw new Error(t('edgeoneSafetyHelp'));
      if(p.kind==='hipmdnsmgr') {
        if(!direct('endpoint_env') && !p.options.endpoint_env || p.options.endpoint_env && !/^HIPM_[A-Z0-9_]{1,59}$/.test(p.options.endpoint_env))throw new Error(t('endpointEnvHelp'));
        if(p.options.domain_id!==undefined && (!/^[1-9][0-9]*$/.test(p.options.domain_id) || BigInt(p.options.domain_id)>9223372036854775807n))throw new Error('domain_id: canonical positive int64');
      }if(names.has(p.name))throw new Error(t('duplicate'));names.add(p.name);
    });
    const recordNames=new Set(),targets=new Set(),ids=new Set(); c.records.forEach(r=>{
      checkKeys(r,['name','provider','domain','subdomain','record_type','record_line','ttl','record_id','create_if_missing','enabled','ip_source','options']);requireStrings(r,['name','provider','domain']);if(typeof r.subdomain!=='string' || !r.subdomain && c.providers.find(p=>p.name===r.provider)?.kind!=='namecheap')throw new Error(t('required'));if(typeof r.record_line!=='string')throw new Error(t('invalidConfig'));
      if(r.options===undefined)r.options={};if(r.record_id===undefined)r.record_id=null;
      if(typeof r.record_id==='number'){if(!positive(r.record_id))throw new Error(t('invalidRecordId'));r.record_id=String(r.record_id);}
      if(r.record_id!==null && (typeof r.record_id!=='string' || !/^[A-Za-z0-9_.-]{1,128}$/.test(r.record_id) || r.record_id==='0'))throw new Error(t('invalidRecordId'));
      if(recordNames.has(r.name))throw new Error(t('duplicate'));recordNames.add(r.name);
      if(!names.has(r.provider)||!['A','AAAA'].includes(r.record_type)||!positive(r.ttl))throw new Error(t('invalidConfig'));
      const rd=descriptor(c.providers.find(p=>p.name===r.provider).kind);
      if(!r.record_line.trim() && !['callback','trafficroute','namecheap'].includes(rd.kind))throw new Error(t('required'));
      if(rd.kind==='namecheap' && (r.ttl<60 || r.ttl>60000 || !['','default','默认'].includes(r.record_line) || r.record_id!==null && !/^namecheap-[a-f0-9]{64}$/.test(r.record_id)))throw new Error(t('namecheapIdHelp')+' '+t('namecheapSafetyHelp'));
      if(rd.kind==='trafficroute'  && (r.ttl>86400 || !pathId(targetLine(rd.kind,r.record_line)) || r.record_id!==null && (!/^[1-9][0-9]*$/.test(r.record_id) || BigInt(r.record_id)>9223372036854775807n)))throw new Error(t('trafficSafetyHelp'));
      if(rd.kind==='callback' && (r.record_id!==null || r.create_if_missing!==false || Object.keys(r.options).length))throw new Error(t('callbackIgnoredHelp'));
      if(rd.kind==='hipmdnsmgr' && (!/^[\x21-\x7e]{1,128}$/.test(r.record_line)))throw new Error(t('nativeLineHelp'));
      validateOptions(r.options,rd.record_options);
      const p=c.providers.find(p=>p.name===r.provider);
      if(batchHelp[rd.kind]) {
        if(rd.kind!=='callback' && /[\x00-\x1f\x7f-\x9f]/.test(r.record_line))throw new Error(t(batchHelp[rd.kind]));
        const hostname=v=>typeof v==='string' && v.length>0 && v.length<=253 && v.split('.').every(l=>l.length>0 && l.length<=63 && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(l));
        if(!r.domain.includes('.') || !hostname(r.domain) || r.subdomain!=='@' && !(rd.kind==='namecheap' && r.subdomain==='') && !hostname(r.subdomain) || (r.subdomain==='@' || r.subdomain===''?r.domain:`${r.subdomain}.${r.domain}`).length>253)throw new Error(t(batchHelp[rd.kind]));
      }
      if(rd.kind==='namecheap' && r.domain.toLowerCase()!==`${p.options.sld}.${p.options.tld}`.toLowerCase())throw new Error(t('namecheapSafetyHelp'));
      if(rd.kind==='huaweicloud' && (r.ttl<300 || !['default','默认','default_view'].includes(r.record_line) || r.record_id!==null && !pathId(r.record_id) || r.options.zone_id!==undefined && (!pathId(r.options.zone_id) || p.options.zone_id!==undefined && p.options.zone_id!==r.options.zone_id)))throw new Error(t('huaweiSafetyHelp'));
      if(rd.kind==='baiducloud' && (r.domain.length>64 || r.ttl<60 || r.ttl>3600 || !['DEFAULT','default','默认','CMNET','CNC','EDU','SEARCH'].includes(r.record_line) || r.record_id!==null && (!/^[1-9][0-9]*$/.test(r.record_id) || BigInt(r.record_id)>2147483647n)))throw new Error(t('baiduSafetyHelp'));
      if(rd.kind==='edgeone' && (r.ttl<60 || r.ttl>86400 || r.record_id!==null && !r.record_id.startsWith('record-')))throw new Error(t('edgeoneSafetyHelp'));
      if(r.ttl>604800)throw new Error('TTL: 1..604800');
      const line=targetLine(rd.kind,r.record_line);
      const target=JSON.stringify([r.provider,r.domain.toLowerCase(),rd.kind==='namecheap' && r.subdomain===''?'@':r.subdomain.toLowerCase(),r.record_type,line]);
      const id=JSON.stringify([r.provider,r.domain.toLowerCase(),r.record_id]);
      if(targets.has(target) || (r.record_id!==null && ids.has(id)))throw new Error(t('duplicate'));
      targets.add(target);if(r.record_id!==null)ids.add(id);
      if(typeof r.enabled!=='boolean'||typeof r.create_if_missing!=='boolean')throw new Error(t('invalidBoolean'));
      checkKeys(r.ip_source,['kind','value','regex']);if(!['url','static','interface'].includes(r.ip_source.kind))throw new Error(t('invalidSource'));requireStrings(r.ip_source,['value']);
      if(Object.hasOwn(r.ip_source,'regex') && (r.ip_source.kind!=='interface' || typeof r.ip_source.regex!=='string'))throw new Error(t('invalidInterfaceRegex'));
    }); return c;
  }
  async function api(path,options={}) {
    const epoch=state.epoch, token=options.public?'':state.token;
    const controller=new AbortController(); const timer=setTimeout(()=>controller.abort(),path==='/api/run'?180000:20000);
    try {
      const response=await fetch(path,{...options,headers:{'Accept':'application/json',...(options.body?{'Content-Type':'application/json'}:{}),...(token?{'Authorization':`Bearer ${token}`}:{})},cache:'no-store',credentials:'same-origin',signal:controller.signal});
      const body=await response.text(); let data=null; try {data=body?JSON.parse(body):null;}catch(_){data={message:body};}
      if(epoch!==state.epoch)throw new Error('Session changed');
      if(!response.ok) {
        const detail=data?.error || data; const pieces=[response.status===409?t('busy'):response.status===401||response.status===403?t('authError'):`${t('apiFailure')} (${response.status})`];
        if(detail && typeof detail==='object') { for(const key of ['stage','code','message','hint','request_id','http_status','retryable'])if(detail[key]!==undefined&&detail[key]!==null)pieces.push(`${key}: ${typeof detail[key]==='object'?json(detail[key]):String(detail[key])}`); if(!pieces.slice(1).length)pieces.push(json(detail)); } else if(detail)pieces.push(String(detail));
        if((response.status===401||response.status===403) && !options.allowUnauthorized){disconnect(false);notice(pieces.join('\n'),'error');}
        const err=new Error(pieces.join('\n'));err.status=response.status;throw err;
      }
      if(data===null && path==='/api/auth/logout')return {};if(data===null)throw new Error(t('invalidConfig'));
      return data;
    } catch(err) { if(err.name==='AbortError')throw new Error(`${t('networkError')} (timeout)`); if(err instanceof TypeError)throw new Error(t('networkError'));throw err; } finally {clearTimeout(timer);}
  }
  function field(parent,key,value,onChange,{type='text',options=null,placeholder='',required=true,min=null}={}) {
    const label=node('label');label.append(node('span','',t(key)));const input=node(options?'select':'input');
    if(options)options.forEach(([v,labelKey])=>{const option=node('option','',labelKey?t(labelKey):v);option.value=v;input.append(option);});else input.type=type;
    input.value=value ?? ''; input.required=required; input.placeholder=placeholder;if(min!==null){input.min=min;input.step='1';}if(type==='text'){input.autocomplete='off';input.spellcheck=false;}
    input.addEventListener(options?'change':'input',()=>{onChange(type==='number'?(input.value===''?null:Number(input.value)):input.value);markDirty();});label.append(input);parent.append(label);return input;
  }
  function checkbox(parent,key,value,onChange,disabled=false) { const label=node('label','checkbox-label'),input=node('input');input.type='checkbox';input.checked=value;input.disabled=disabled;input.addEventListener('change',()=>{onChange(input.checked);markDirty();});label.append(input,node('span','',t(key)));parent.append(label); }
  function cardHeader(card,title,removeAction) { const header=node('div','edit-card-header');header.append(node('strong','',title));const button=node('button','button quiet small',t('remove'));button.type='button';button.addEventListener('click',removeAction);header.append(button);card.append(header); }
  function optionsForm(parent,descriptors,values,heading,kind) {
    if(!descriptors.length)return;
    const box=node('div','descriptor-options');box.append(node('h4','',t(heading)));const grid=node('div','descriptor-grid');
    descriptors.forEach(d=>field(grid,d.key==='domain_id' && kind==='hipmdnsmgr'?'managerDomainId':d.key==='region' && kind==='huaweicloud'?'huaweiRegion':d.key==='zone_id' && kind==='edgeone'?'nativeZoneId':kind==='namecheap'?({scope:'namecheapScope',write_mode:'namecheapWriteMode',environment:'namecheapEnvironment',sld:'namecheapSld',tld:'namecheapTld',client_ip_env:'namecheapClientIpEnv'}[d.key]||optionLabel(d)):kind==='trafficroute'?({scope:'trafficScope',api_version:'trafficVersion',region:'trafficRegion',zone_id:'trafficZone'}[d.key]||optionLabel(d)):kind==='callback'?({mode:'callbackMode',ttl_mode:'callbackTtl'}[d.key]||optionLabel(d)):optionLabel(d),values[d.key],v=>{if(v==='')delete values[d.key];else values[d.key]=v;},{required:d.required,options:d.key==='proxied'?[['','unset'],['true','true'],['false','false']]:null,placeholder:kind==='namecheap'?({scope:'basicdns_plain',write_mode:'exclusive_full_zone',environment:'production / sandbox',sld:'example',tld:'com / co.uk',client_ip_env:'NAMECHEAP_ACCOUNT_SERVER_IP'}[d.key]||''):kind==='trafficroute'?({scope:'public_dns',api_version:'2018-08-01',region:'cn-beijing',zone_id:'positive int64 ZID'}[d.key]||''):kind==='callback'?({endpoint_env:'CALLBACK_ACCOUNT_ENDPOINT',mode:'json_post',verification:'unverified',delivery:'every_run',ttl_mode:'metadata_only'}[d.key]||''):d.key==='region'?(kind==='huaweicloud'?'cn-north-4':'cn-hangzhou'):d.key==='zone_id'?(kind==='edgeone'?'zone-...':'Zone ID'):d.key==='project_id'?'regional IAM project ID':d.key==='resource_id'?'registered-domain resourceId':d.key==='mode'?'dns':d.key==='scope'?'teodns':d.key==='api_version'?'2022-09-01':d.key==='team_id'?'team_...':''}));box.append(grid);if(descriptors.some(d=>d.key==='endpoint_env'))box.append(node('p','field-help',t(kind==='callback'?'callbackEndpointHelp':'endpointEnvHelp')));if(descriptors.some(d=>d.key==='proxied'))box.append(node('p','field-help',t('proxyHelp')));parent.append(box);
  }
  function retainOptions(values,descriptors) {const result={};for(const d of descriptors)if(Object.hasOwn(values,d.key))result[d.key]=values[d.key];return result;}
  function switchProviderKind(p,kind) {
    const old=descriptor(p.kind),next=descriptor(kind);if(!next)return;
    p.kind=kind;if(old?.kind!==next.kind){delete p.credentials;credentialDrafts.delete(p);}
    credentialKeys.forEach(key=>{const a=old?.credential_fields.find(d=>d.key===key),b=next.credential_fields.find(d=>d.key===key);if(!a || !b || a.env_prefix!==b.env_prefix)p[key]='';});
    p.options=old?.kind===next.kind?retainOptions(p.options,next.options):{};
    state.config.records.filter(r=>r.provider===p.name).forEach(r=>{r.options=retainOptions(r.options,next.record_options);r.record_id=null;if(next.kind==='callback')r.create_if_missing=false;if(next.kind==='namecheap')r.record_line='default';});
    markDirty();renderConfig();notice(t('switchDraft'));
  }
  function renderRegistry() {
    const pending=state.registry.filter(p=>!p.implemented),box=$('pendingProviders');box.replaceChildren();box.hidden=!pending.length;
    if(pending.length){box.append(node('strong','',t('pendingProviders')));const list=node('p','',pending.map(p=>`${p.label} (${p.kind})`).join(' · '));box.append(list);}
  }
  function renderSourceValue(parent, record) {
    const source=record.ip_source;
    parent.replaceChildren();
    if(source.kind!=='interface'){
      const placeholder=source.kind==='url'?'https://api.ipify.org':record.record_type==='AAAA'?'2001:db8::1':'203.0.113.1';
      field(parent,'ipValue',source.value,v=>source.value=v,{placeholder});
      parent.append(node('p','field-help',t(`${source.kind}Help`)));
      return;
    }
    const interfaces=(state.interfaces || []).filter(item=>item.ipv4.length || item.ipv6.length);
    const options=[['','chooseInterface'],...interfaces.map(item=>[item.name,null])];
    const addresses=node('p','field-help');
    const preview=node('p','field-help interface-preview');
    preview.setAttribute('role','status');
    let previewTimer, previewRevision=0;
    const family=record.record_type==='AAAA'?'ipv6':'ipv4';
    const showAddresses=()=>{
      const ips=interfaces.find(item=>item.name===source.value)?.[family];
      if(ips){
        const label=family==='ipv6'?'IPv6':'IPv4';
        addresses.textContent=`${label} · ${ips.length?ips.join(', '):t('noInterfaceAddresses')}`;
      }else if(!state.interfaces){
        addresses.textContent=t('interfaceUnavailable');
      }else if(source.value){
        addresses.textContent=`${source.value} (${t('interfaceMissing')})`;
      }else{
        addresses.textContent=interfaces.length?'':t('noInterfaces');
      }
      addresses.hidden=!addresses.textContent;
    };
    const updatePreview=()=>{
      clearTimeout(previewTimer);
      const revision=++previewRevision;
      const selected=interfaces.some(item=>item.name===source.value);
      preview.textContent='';
      if(!selected && !source.regex)return;
      const body=json({
        record_type:record.record_type,
        ip_source:{...source,value:selected?source.value:''}
      });
      const current=()=>revision===previewRevision && $('records').contains(preview);
      previewTimer=setTimeout(async()=>{
        if(!current())return;
        try {
          const matches=await api('/api/interfaces/preview',{method:'POST',body});
          if(!current() || !selected)return;
          preview.textContent=matches.length
            ? `${t('interfacePreview')} · ${matches.map((ip,index)=>index===0?`${ip} (${t('interfacePreviewSelected')})`:ip).join(', ')}`
            : t('interfacePreviewEmpty');
        } catch(err) {
          if(current())preview.textContent=t(err.status===422?'interfacePreviewError':'interfacePreviewUnavailable');
        }
      },200);
    };
    const selected=interfaces.some(item=>item.name===source.value)?source.value:'';
    field(parent,'interface',selected,v=>{
      source.value=v;
      showAddresses();
      updatePreview();
    },{options,required:false});
    showAddresses();
    parent.append(addresses);
    field(parent,'interfaceRegex',source.regex,v=>{
      if(v)source.regex=v;
      else delete source.regex;
      updatePreview();
    },{required:false});
    parent.append(preview,node('p','field-help',t('interfaceRegexHelp')));
    updatePreview();
  }
  function renderConfig() {
    const c=state.config;if(!c)return;
    $('interval').value=c.interval_secs;$('timeout').value=c.timeout_secs;$('configLogLevel').value=c.log_level;
    $('providers').replaceChildren();
    renderRegistry();
    c.providers.forEach((p,index)=>{const card=node('div','edit-card');cardHeader(card,`${t('provider')} ${index+1}`,()=>{c.providers.splice(index,1);markDirty();renderConfig();});const fields=node('div','provider-fields');
      field(fields,'providerName',p.name,v=>{const old=p.name;p.name=v;c.records.forEach(r=>{if(r.provider===old)r.provider=v;});renderProviderOptions();});
      field(fields,'providerKind',p.kind,v=>switchProviderKind(p,v),{options:state.registry.filter(d=>d.implemented).map(d=>[d.kind,providerLabel(d)])});
      const d=descriptor(p.kind);
      if(d) {
        for(const f of [...d.credential_fields,...d.options.filter(f=>['endpoint_env','client_ip_env'].includes(f.key))]) {
          const draft=credentialDrafts.get(p),stored=p.credentials?.[f.key];
          const value=draft && Object.hasOwn(draft,f.key)?draft[f.key]:stored===CONFIGURED?'':stored || '';
          const label={endpoint_env:'directEndpoint',client_ip_env:'directClientIp',secret_id_env:'credentialId',secret_key_env:'credentialSecret',token_env:'credentialToken'}[f.key];
          const input=field(fields,label,value,v=>{let values=credentialDrafts.get(p);if(!values){values={};credentialDrafts.set(p,values);}values[f.key]=v;},{type:'password',required:false,placeholder:stored===CONFIGURED?t('configured'):t('notConfigured')});
          input.dataset.directCredential=f.key;input.autocomplete='new-password';
        }
      }
      card.append(fields);if(d){card.append(node('p','field-help',t('directHelp')));const refs=node('details','credential-refs');refs.append(node('summary','',t('advancedRefs')));const grid=node('div','descriptor-grid');d.credential_fields.forEach(f=>{const input=field(grid,credentialLabel(p.kind,f),p[f.key],v=>p[f.key]=v,{required:false,placeholder:f.env_prefix+({secret_id_env:'SECRET_ID',secret_key_env:'SECRET_KEY',token_env:'TOKEN'})[f.key]});input.maxLength=128;input.pattern=`(?:${f.env_prefix}|DDNS_)[A-Z0-9_]+`;input.title=t('invalidEnv');});refs.append(grid);optionsForm(refs,d.options.filter(f=>['endpoint_env','client_ip_env'].includes(f.key)).map(f=>({...f,required:false})),p.options,'providerOptions',p.kind);card.append(refs);optionsForm(card,d.options.filter(f=>!['endpoint_env','client_ip_env'].includes(f.key)),p.options,'providerOptions',p.kind);}if(batchHelp[p.kind])card.append(node('p','field-help',t(batchHelp[p.kind])));$('providers').append(card);});
    if(!c.providers.length)$('providers').append(node('p','empty-inline',t('emptyProviders')));
    $('records').replaceChildren();
    c.records.forEach((r,index)=>{const card=node('div',`edit-card record-card${r.enabled?'':' is-disabled'}`);cardHeader(card,`${t('records')} ${index+1}`,()=>{c.records.splice(index,1);markDirty();renderConfig();});const grid=node('div','record-fields');
      field(grid,'recordName',r.name,v=>r.name=v,{placeholder:'home-ipv4'});
      const provider=field(grid,'provider',r.provider,v=>{r.provider=v;r.options=retainOptions(r.options,recordDescriptor(r)?.record_options || []);r.record_id=null;if(recordDescriptor(r)?.kind==='callback')r.create_if_missing=false;if(recordDescriptor(r)?.kind==='namecheap')r.record_line='default';markDirty();renderConfig();notice(t('switchDraft'));},{options:[['','chooseProvider'],...c.providers.map(p=>[p.name,null])]});provider.dataset.providerIndex=String(index);
      field(grid,'domain',r.domain,v=>r.domain=v,{placeholder:'example.com'});field(grid,'subdomain',r.subdomain,v=>r.subdomain=v,{placeholder:'@ / home'});
      const sourceValue=node('div','ip-source-value');
      field(grid,'recordType',r.record_type,v=>{r.record_type=v;renderSourceValue(sourceValue,r);},{options:[['A',null],['AAAA',null]]});const lineInput=field(grid,'recordLine',r.record_line,v=>r.record_line=v,{placeholder:locale==='zh'?'默认':'default'});if(['callback','namecheap'].includes(recordDescriptor(r)?.kind))lineInput.disabled=true;
      const ttlInput=field(grid,'ttl',r.ttl,v=>r.ttl=v,{type:'number',min:recordDescriptor(r)?.kind==='huaweicloud'?300:['baiducloud','edgeone','namecheap'].includes(recordDescriptor(r)?.kind)?60:1});ttlInput.max=recordDescriptor(r)?.kind==='namecheap'?60000:recordDescriptor(r)?.kind==='baiducloud'?3600:recordDescriptor(r)?.kind==='edgeone'?86400:604800;if(recordDescriptor(r)?.kind==='dynv6'){ttlInput.disabled=true;ttlInput.parentNode.append(node('small','credential-description',t('providerManagedTtl')));}const idInput=field(grid,'recordId',r.record_id,v=>r.record_id=v===''?null:v,{required:false});if(recordDescriptor(r)?.kind==='callback'){idInput.disabled=true;grid.append(node('p','field-help',t('callbackIgnoredHelp')));}idInput.maxLength=128;idInput.pattern='[A-Za-z0-9_.-]{1,128}';idInput.title=t('invalidRecordId');idInput.addEventListener('input',()=>idInput.setCustomValidity(idInput.value==='0' || idInput.validity.patternMismatch?t('invalidRecordId'):''));idInput.parentNode.append(node('small','credential-description',t(recordDescriptor(r)?.kind==='namecheap'?'namecheapIdHelp':'recordIdHelp')+(['tencentcloud','alidns','dnspod'].includes(recordDescriptor(r)?.kind)?` ${t('numericRecordIdHelp')}`:'')));
      const rd=recordDescriptor(r);if(batchHelp[rd?.kind])grid.append(node('p','field-help',t(batchHelp[rd.kind])));if(rd?.kind==='hipmdnsmgr')grid.append(node('p','field-help record-line-help',t('nativeLineHelp')));if(rd?.kind==='namesilo')grid.append(node('p','field-help',t('namesiloSafetyHelp')));if(rd?.kind==='gcore')grid.append(node('p','field-help',t('gcoreSafetyHelp')));if(rd?.kind==='spaceship')grid.append(node('p','field-help',t('spaceshipSafetyHelp')));if(rd?.kind==='alidns')grid.append(node('p','field-help record-line-help',t('aliLineHelp')));
      const source=node('div','ip-source');
      field(source,'ipKind',r.ip_source.kind,v=>{
        if(v==='interface' || r.ip_source.kind==='interface')r.ip_source.value='';
        if(v!=='interface')delete r.ip_source.regex;
        r.ip_source.kind=v;
        renderSourceValue(sourceValue,r);
      },{options:[['url','url'],['static','static'],['interface','interface']]});
      renderSourceValue(sourceValue,r);source.append(sourceValue);grid.append(source);
      const toggles=node('div','record-toggles');checkbox(toggles,'enabled',r.enabled,v=>{r.enabled=v;card.classList.toggle('is-disabled',!v);});checkbox(toggles,'createMissing',r.create_if_missing,v=>r.create_if_missing=v,rd?.kind==='callback');card.append(grid);if(rd)optionsForm(card,rd.record_options,r.options,'recordOptions');card.append(toggles);$('records').append(card);});
    if(!c.records.length)$('records').append(node('p','empty-inline',t('emptyRecords')));
    if(!state.jsonDirty)$('configJson').value=json(maskedConfig(c));updateControls();
  }
  function renderProviderOptions() { document.querySelectorAll('[data-provider-index]').forEach(select=>{const r=state.config.records[Number(select.dataset.providerIndex)];select.replaceChildren();[['',t('chooseProvider')],...state.config.providers.map(p=>[p.name,p.name])].forEach(([v,label])=>{const option=node('option','',label);option.value=v;select.append(option);});select.value=r.provider;}); }
  function empty(parent,title,help) {const n=node('div','empty-state');n.append(node('span','empty-icon','◈'),node('strong','',t(title)));if(help)n.append(node('p','',t(help)));parent.append(n);}
  function renderStatus() {
    const s=state.status, report=s?.last_run;
    text('runningValue',s?t(state.runPending||s.running?'running':'idle'):'—');text('runningDetail',s?t(state.runPending||s.running?'inProgress':report?'finished':'noRun'):t('connectFirst'));
    if(state.config){const c=state.config;text('recordCount',`${c.records.filter(r=>r.enabled).length} / ${c.records.length}`);text('providerCount',`${c.providers.length} ${t('providerTotal')}`);}else{text('recordCount','—');text('providerCount','—');}
    text('lastRunValue',report?t(report.dry_run?'dryRun':'realRun'):'—');text('lastRunDetail',report?date(report.finished_at||report.started_at):t('noRun'));
    text('lastRefresh',state.lastRefresh?`${t('refreshed')} ${date(state.lastRefresh)}`:t('authenticatedOnly'));
    $('results').replaceChildren();
    if(!report){empty($('results'),'noReport','noReportHelp');text('reportMeta',t('reportHelp'));text('reportBadge',t('waiting'));$('reportBadge').className='badge neutral';return;}
    text('reportMeta',`Run ${report.run_id ?? '—'} · ${date(report.started_at)} → ${date(report.finished_at)} · ${t(report.dry_run?'nonModifying':'realRun')}`);
    text('reportBadge',t(report.dry_run?'dryRun':'realRun'));$('reportBadge').className=`badge ${report.dry_run?'safe':'warning'}`;
    const results=Array.isArray(report.results)?report.results:[];
    if(!results.length)empty($('results'),'noReport');
    results.forEach(result=>{const card=node('article','result-card');const header=node('div','result-header');header.append(node('strong','',result.name??t('unknown')));const status=String(result.status??'unknown');const unverified=['callback_accepted_unverified','would_call_unverified'].includes(status);const bad=!!result.error||['failed','error'].includes(status.toLowerCase());header.append(node('span',`badge ${bad?'danger':unverified?'warning':['success','updated','unchanged','created','would_update','would_create','ok','validated'].includes(status.toLowerCase())?'safe':'neutral'}`,t(status)));card.append(header);
      const ip=node('div','result-ip');ip.append(node('span','',t('ip')),node('code','',result.ip??'—'));card.append(ip);
      if(result.error){const details=node('dl','error-details');for(const [key,label] of [['stage','stage'],['code','code'],['message','message'],['hint','hint'],['request_id','requestId'],['http_status','httpStatus'],['retryable','retryable']]){details.append(node('dt','',t(label)),node('dd',key==='hint'?'error-hint':'',result.error[key]===null||result.error[key]===undefined?'—':key==='retryable'?t(result.error[key]?'yes':'no'):String(result.error[key])));}card.append(details);}
      if(result.outcome!==null&&result.outcome!==undefined){const details=node('details','outcome');details.append(node('summary','',t('outcome')),node('pre','',json(result.outcome)));card.append(details);}
      const raw=node('details','outcome');raw.append(node('summary','',t('raw')),node('pre','',json(result)));card.append(raw);$('results').append(card);
    });
  }
  function renderLogs() {
    $('logEntries').replaceChildren();text('logCount',`${state.logs.length} ${t('logsTotal')}`);
    if(!state.logs.length){empty($('logEntries'),state.authenticated?'noMatchingLogs':'noLogs');return;}
    state.logs.forEach(log=>{const row=node('article','log-row');row.append(node('time','log-time',date(log.timestamp)));const level=String(log.level??'unknown').toLowerCase();row.append(node('span',`log-level ${['trace','debug','info','warn','error'].includes(level)?level:'unknown'}`,level.toUpperCase()));const body=node('div','log-body');body.append(node('div','log-message',log.message??''));if(log.fields&&Object.keys(log.fields).length){const details=node('details','log-fields');details.append(node('summary','',`${Object.keys(log.fields).length} ${t('fields')}`),node('pre','',json(log.fields)));body.append(details);}row.append(body);$('logEntries').append(row);});
  }
  function acceptConfig(value) {const c=validateConfig(value);state.config=maskedConfig(c);credentialDrafts=new WeakMap();state.dirty=false;state.jsonDirty=false;$('runtimeLevel').value=c.log_level;renderConfig();renderStatus();}
  async function loadConfig() {const epoch=state.epoch;const c=await api('/api/config');if(epoch===state.epoch)acceptConfig(c);}
  async function loadInterfaces() {
    const epoch=state.epoch;
    let interfaces=null;
    try {
      const value=await api('/api/interfaces');
      if(Array.isArray(value) && value.every(item=>typeof item?.name==='string' &&
        [item.ipv4,item.ipv6].every(ips=>Array.isArray(ips) && ips.every(ip=>typeof ip==='string'))))interfaces=value;
    } catch(_) {
      // Keep configuration available if interface discovery fails.
    }
    if(epoch===state.epoch)state.interfaces=interfaces;
  }
  function acceptSettings(value) {
    checkKeys(value,['listen','active_listen','username','token_configured']);
    if(typeof value.listen!=='string' || typeof value.active_listen!=='string' || typeof value.username!=='string' || typeof value.token_configured!=='boolean')throw new Error(t('apiFailure'));
    state.settings=value;$('settingsListen').value=value.listen;$('activeListen').value=value.active_listen;$('settingsUsername').value=value.username;
    $('settingsToken').value='';$('settingsPassword').value='';$('changeToken').checked=false;text('tokenConfigured',t(value.token_configured?'configured':'notConfigured'));updateControls();return value;
  }
  async function loadSettings() {const epoch=state.epoch;const value=await api('/api/settings');if(epoch===state.epoch)acceptSettings(value);}
  async function loadLogs() {
    if(!state.authenticated||state.logsPending)return;state.logsPending=true;const epoch=state.epoch;
    try {const query=new URLSearchParams();if($('logFilter').value)query.set('level',$('logFilter').value);if($('search').value.trim())query.set('search',$('search').value.trim());const logs=await api(`/api/logs${query.size?'?'+query.toString():''}`);if(!Array.isArray(logs))throw new Error(t('apiFailure'));if(epoch===state.epoch){state.logs=logs;renderLogs();}}finally{state.logsPending=false;}
  }
  async function refresh() {
    if(!state.authenticated||state.refreshing)return;state.refreshing=true;const epoch=state.epoch;updateControls();
    try {const outcomes=await Promise.allSettled([api('/api/status'),loadLogs()]);if(epoch!==state.epoch)return;
      if(outcomes[0].status==='fulfilled'){const s=outcomes[0].value;if(typeof s.running!=='boolean')throw new Error(t('apiFailure'));state.status=s;state.lastRefresh=new Date().toISOString();renderStatus();}
      const error=outcomes.find(r=>r.status==='rejected');if(error)notice(error.reason.message,'error');
    } catch(err){if(epoch===state.epoch)notice(err.message,'error');}finally{state.refreshing=false;updateControls();}
  }
  function disconnect(show=true) {
    state.epoch++;clearInterval(pollTimer);pollTimer=null;clearTimeout(searchTimer);storage.remove('sessionStorage','ddns.token');wipePasswords();
    Object.assign(state,{token:'',authenticated:false,connecting:false,authMode:state.initialized===false?'setup':'login',config:null,settings:null,registry:[],interfaces:null,status:null,logs:[],dirty:false,jsonDirty:false,lastRefresh:null,runPending:false});
    $('token').value='';$('providers').replaceChildren();$('records').replaceChildren();$('configJson').value='';$('interval').value='';$('timeout').value='';for(const id of ['settingsListen','activeListen','settingsUsername'])$(id).value='';text('tokenConfigured','');renderRegistry();renderStatus();renderLogs();updateControls();if(show)notice(t('disconnected'));
  }
  async function enterConsole(config=null) {
    const epoch=state.epoch;state.registry=validateRegistry(await api('/api/providers'));
    await loadInterfaces();if(epoch!==state.epoch)return;
    if(config)acceptConfig(config);else await loadConfig();if(epoch!==state.epoch)return;
    state.authenticated=true;state.authMode='login';state.initialized=true;wipePasswords();updateControls();
    if(state.token)storage.set('sessionStorage','ddns.token',state.token);
    notice(t('connected'),'success');clearInterval(pollTimer);pollTimer=setInterval(refresh,5000);
    await Promise.all([refresh(),loadSettings()]);
  }
  async function checkAuth() {
    if(state.connecting)return;state.connecting=true;state.authMode='loading';updateControls();const epoch=state.epoch;
    try {
      const status=await api('/api/auth/status',{public:true,allowUnauthorized:true});if(typeof status?.initialized!=='boolean')throw new Error(t('apiFailure'));if(epoch!==state.epoch)return;
      state.initialized=status.initialized;
      if(!status.initialized){state.authMode='setup';state.token='';storage.remove('sessionStorage','ddns.token');}
      else {state.token='';try {const config=await api('/api/config',{allowUnauthorized:true});await enterConsole(config);}catch(err){if(err.status===401 || err.status===403){state.token='';storage.remove('sessionStorage','ddns.token');state.authMode='login';}else throw err;}}
    } catch(err){if(epoch===state.epoch){state.authMode='error';notice(err.message,'error');}}
    finally{state.connecting=false;updateControls();}
  }
  async function connect(event) {
    event?.preventDefault();if(state.connecting || state.authenticated)return;const setup=state.authMode==='setup';let account;
    try{account=validateAccount($('username').value,$('password').value,$('confirmPassword').value,setup);}catch(err){notice(err.message,'error');return;}
    state.epoch++;const epoch=state.epoch;state.token='';state.connecting=true;updateControls();
    try {const result=await api(setup?'/api/auth/setup':'/api/auth/login',{method:'POST',body:json(account),public:true,allowUnauthorized:true});if(typeof result?.username!=='string')throw new Error(t('apiFailure'));state.initialized=true;state.authMode='login';$('username').value=result.username;wipePasswords();await enterConsole();}
    catch(err){if(epoch===state.epoch){wipePasswords();notice(err.message,'error');if(setup){if(err.status===409){state.initialized=true;state.authMode='login';}else {try{const status=await api('/api/auth/status',{public:true,allowUnauthorized:true});if(epoch===state.epoch && status?.initialized===true){state.initialized=true;state.authMode='login';}}catch(_){/* Keep setup retryable when the network is down. */}}}}}
    finally{state.connecting=false;updateControls();}
  }
  async function connectToken(event) {
    event.preventDefault();if(state.connecting || state.authenticated)return;const token=$('token').value.trim();if(!token){notice(t('missingToken'),'error');return;}
    state.epoch++;state.token=token;state.connecting=true;updateControls();
    try{await enterConsole();}catch(err){state.token='';storage.remove('sessionStorage','ddns.token');notice(err.message,'error');}finally{state.connecting=false;updateControls();}
  }
  async function logout() {
    if(state.connecting)return;state.connecting=true;updateControls();
    try{await api('/api/auth/logout',{method:'POST'});disconnect();}
    catch(err){notice(err.message,'error');}finally{wipePasswords();state.connecting=false;updateControls();}
  }
  async function run(dryRun) {
    if(!state.authenticated||state.runPending||state.status?.running||state.saving)return;
    state.runPending=true;const epoch=state.epoch;updateControls();renderStatus();notice(`${t('runStarted')} ${t(dryRun?'nonModifying':'realRun')}`);
    try {const report=await api('/api/run',{method:'POST',body:json({dry_run:dryRun})});if(epoch!==state.epoch)return;state.status={running:false,last_run:report};renderStatus();notice(t('runDone'),Array.isArray(report.results)&&report.results.some(r=>r.error||['error','failed'].includes(String(r.status).toLowerCase()))?'error':'success');}
    catch(err){if(epoch===state.epoch){if(err.status===409)state.status={...(state.status||{}),running:true};notice(err.message,'error');}}
    finally{state.runPending=false;updateControls();renderStatus();if(state.authenticated)refresh();}
  }
  $('authForm').addEventListener('submit',connect);$('disconnect').addEventListener('click',logout);$('tokenForm').addEventListener('submit',connectToken);$('authRetry').addEventListener('click',checkAuth);$('refresh').addEventListener('click',refresh);
  $('locale').addEventListener('change',()=>{locale=$('locale').value;storage.set('localStorage','ddns.locale',locale);translate();});
  for(const [id,key] of [['interval','interval_secs'],['timeout','timeout_secs'],['configLogLevel','log_level']])$(id).addEventListener(id==='configLogLevel'?'change':'input',()=>{if(state.config){state.config[key]=id==='configLogLevel'?$(id).value:Number($(id).value);markDirty();}});
  $('addProvider').addEventListener('click',()=>{state.config.providers.push({name:'',kind:state.registry.find(p=>p.implemented)?.kind || 'tencentcloud',secret_id_env:'',secret_key_env:'',token_env:'',options:{}});markDirty();renderConfig();});
  $('addRecord').addEventListener('click',()=>{state.config.records.push({name:'',provider:state.config.providers[0]?.name||'',domain:'',subdomain:'@',record_type:'A',record_line:state.config.providers[0]?.kind==='hipmdnsmgr'?'default':'默认',ttl:600,record_id:null,options:{},create_if_missing:false,enabled:false,ip_source:{kind:'url',value:''}});markDirty();renderConfig();});
  $('jsonDetails').addEventListener('toggle',()=>{if($('jsonDetails').open&&state.config&&!state.jsonDirty)$('configJson').value=json(maskedConfig(state.config));});
  $('configJson').addEventListener('input',()=>{state.jsonDirty=true;updateControls();});
  $('applyJson').addEventListener('click',()=>{try{const c=validateConfig(JSON.parse($('configJson').value));for(const p of c.providers)for(const value of Object.values(p.credentials || {}))if(value && value!==CONFIGURED)throw new Error(t('rawSecretJson'));state.config=c;credentialDrafts=new WeakMap();state.jsonDirty=false;markDirty();renderConfig();notice(t('jsonApplied'),'success');}catch(err){notice(`${t('invalidConfig')}\n${err.message}`,'error');}});
  $('reloadConfig').addEventListener('click',async()=>{if((state.dirty||state.jsonDirty)&&!window.confirm(t('unsavedConfirm')))return;state.saving=true;const epoch=state.epoch;updateControls();try{await loadInterfaces();if(epoch===state.epoch)await loadConfig();}catch(err){notice(err.message,'error');}finally{state.saving=false;updateControls();}});
  $('saveConfig').addEventListener('click',async()=>{
    if(state.saving||!state.config)return;if(state.jsonDirty){notice(t('jsonPending'),'error');return;}
    try{validateConfig(configPayload(state.config));for(const input of $('configFields').querySelectorAll('input,select'))if(!input.checkValidity()){input.reportValidity();return;}}catch(err){notice(`${t('invalidConfig')}\n${err.message}`,'error');return;}
    state.saving=true;const epoch=state.epoch;updateControls();
    try{const result=await api('/api/config',{method:'PUT',body:json(configPayload(state.config))});if(epoch!==state.epoch)return;wipePasswords();acceptConfig(result);notice(t('savedNotice'),'success');}catch(err){if(epoch===state.epoch)notice(err.message,'error');}finally{state.saving=false;updateControls();}
  });
  $('reloadSettings').addEventListener('click',async()=>{state.settingsPending=true;updateControls();try{await loadSettings();}catch(err){notice(err.message,'error');}finally{state.settingsPending=false;updateControls();}});
  $('settingsForm').addEventListener('submit',async event=>{
    event.preventDefault();if(!state.authenticated || !state.settings || state.settingsPending)return;
    const previous=state.settings,username=$('settingsUsername').value.trim(),password=$('settingsPassword').value,changeToken=$('changeToken').checked;
    const payload={listen:$('settingsListen').value.trim(),username};
    try{if(!username || byteLength(username)>64)throw new Error(t('invalidUsername'));if(password)validateAccount(username,password,password);if(!payload.listen)throw new Error(t('required'));}catch(err){notice(err.message,'error');return;}
    if(password)payload.password=password;if(changeToken)payload.token=$('settingsToken').value;
    const relogin=username!==previous.username || !!password || changeToken;
    state.settingsPending=true;const epoch=state.epoch;updateControls();
    try {const result=await api('/api/settings',{method:'PUT',body:json(payload)});if(epoch!==state.epoch)return;const actual=acceptSettings(result);const message=[t('settingsSaved'),`${t('listen')}: ${actual.listen}`,`${t('activeListen')}: ${actual.active_listen}`,actual.listen!==actual.active_listen?t('restartRequired'):'',relogin?t('loginRequired'):''].filter(Boolean).join('\n');text('settingsResult',message);if(relogin){disconnect(false);$('username').value=actual.username;}notice(message,'success');}
    catch(err){if(epoch===state.epoch)notice(err.message,'error');}
    finally{wipePasswords(false);state.settingsPending=false;updateControls();}
  });
  $('diagnose').addEventListener('click',()=>run(true));$('run').addEventListener('click',()=>{if(!$('run').disabled){$('confirmDialog').returnValue='cancel';$('confirmDialog').showModal();}});
  $('confirmDialog').addEventListener('close',()=>{if($('confirmDialog').returnValue==='confirm')run(false);});
  $('runtimeLevel').addEventListener('change',async()=>{const previous=state.runtimeLevel||state.config?.log_level||'info';state.levelPending=true;updateControls();try{const result=await api('/api/log-level',{method:'PUT',body:json({level:$('runtimeLevel').value})});state.runtimeLevel=result.level;$('runtimeLevel').value=result.level;if(state.config&&!state.dirty&&!state.jsonDirty&&state.config.log_level===previous){state.config.log_level=result.level;state.dirty=true;renderConfig();}notice(t('levelSet'),'success');await loadLogs();}catch(err){$('runtimeLevel').value=previous;notice(err.message,'error');}finally{state.levelPending=false;updateControls();}});
  const filterLogs=()=>{clearTimeout(searchTimer);searchTimer=setTimeout(()=>loadLogs().catch(err=>notice(err.message,'error')),300);};$('search').addEventListener('input',filterLogs);$('logFilter').addEventListener('change',filterLogs);
  $('export').addEventListener('click',()=>{
    const payload={exported_at:new Date().toISOString(),note:'Sanitized configuration and observed diagnostics. No authorization token. Review domains, IPs, and logs before sharing.',configuration:state.config?maskedConfig(state.config):null,status:state.status,logs:state.logs,log_filter:{level:$('logFilter').value,search:$('search').value}};
    const blob=new Blob([json(payload)+'\n'],{type:'application/json'}),url=URL.createObjectURL(blob),a=node('a');a.href=url;a.download=`ddns-diagnostics-${new Date().toISOString().replace(/[:.]/g,'-')}.json`;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  });
  window.addEventListener('beforeunload',event=>{if(state.dirty||state.jsonDirty){event.preventDefault();event.returnValue='';}});
  $('token').value=state.token;translate();checkAuth();
})();
