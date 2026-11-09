# Registrar state contract review — Now.cn, Eranet, Tnet.hk

Research date: **2026-11-09**. Public first-party articles and actually linked frontend assets only. Read [registrar contract notes](<registrar-contract-notes.md>) and the full [existing NowDNS static review](<nowdns-static-contract-review.md>) first; **no binary was downloaded, inspected again, or executed**. This report is the only repository file created or changed by this investigation. No credentials, login, authentication bypass, API/account inventory requests, DNS lookups, cloud reads/writes, acceptance execution, source/Cargo/catalog changes, or operator contact occurred. No web-search backend was called.

## Result: new route-bound state evidence, not a completed adapter contract

**New first-party frontend evidence directly binds `state=0` to Normal and `state=2` to Pause on the exact GET origin/path published by each brand's current independent-domain API article.** It does **not** support a binary `0/1` enabled/disabled interpretation: no `dnspod.status.1` translation or State=1 filter option was found in the inspected assets.

The actual row action is stronger than a nearby translated string: `row.state === 0` offers **Disable**, whereas `row.state === 2` offers **Enable**. The component reads `response.Data` directly through its list state, without an observed row-state conversion in the traced service → model → component chain. However, the same UI multiplexes `Platform` values `dnscom`, `powerdns`, and another branch; the inspected public source does not expose whether authentication context or backend dispatch changes the returned schema. **Do not categorically call this a different BFF backend:** its getter really matches the current documented URL. Conversely, the match does not prove HMAC-authenticated responses or the newer compiled client's capitalized/legacy route behave identically.

Still unresolved for **each** brand: accepted native HMAC-context State/Status setter or preserve-on-omit behavior, raw Remark/MX/line preservation under documented GET updates, complete unfiltered inventory/count/cap rules, a real positive write acknowledgment, and native ID lifecycle. No adapter is enabled by this report.

## 1. Independent provenance and exact URL comparison

The current independent-domain articles were separately fetched (HTTP 200):

| Brand | Current official article and displayed update | Published list URL | Compiled-client list URL from existing review |
| --- | --- | --- | --- |
| Now.cn | [Independent DNS API](https://help.now.cn/domain/resolve/20260310102214/), 2026-03-10 | `https://www.now.cn/api/dns/DescribeRecordIndex` GET | `https://api.now.cn/api/Dns/DescribeRecordIndex` GET |
| Eranet | [Independent DNS API](https://help.eranet.com/domain/resolve/20260407145050/), 2026-04-08 | `https://www.eranet.com/api/dns/DescribeRecordIndex` GET | `https://www.eranet.com/api/Dns/DescribeRecordIndex` GET |
| Tnet.hk | [Independent DNS API](https://help.tnet.hk/domain/resolve/20260403163405/), 2026-04-03 | `https://www.tnet.hk/api/dns/DescribeRecordIndex` GET | `https://www.tnet.hk/api/Dns/DescribeRecordIndex` GET |

Each actual [Now homepage](https://www.now.cn/), [Eranet homepage](https://www.eranet.com/), and [Tnet homepage](https://www.tnet.hk/) links the corresponding public `/panel/front/domain/bulkregister` page. Those pages returned HTTP 200 without credentials or an authentication redirect:

| Brand | Actual linked public shell | Its literal script source | Main asset bytes / SHA256 |
| --- | --- | --- | --- |
| Now.cn | [Public bulk-registration frontend](https://www.now.cn/panel/front/domain/bulkregister) | [Now main bundle](https://cdn.nowcdn.cn/panel/umi.372aa9e8.js) | 6,610,396 / `073d5220a821b7e4100296cfc2ba9352e4603cd7ffd193ec8433e87db62f1ad9` |
| Eranet | [Public bulk-registration frontend](https://www.eranet.com/panel/front/domain/bulkregister) | [Eranet main bundle](https://eranet-com.oss-accelerate.aliyuncs.com/t/panel/umi.3a4767ca.js) | 6,609,941 / `77244a94b9d3adea5f79353f36ef797f731b24153dbe38505b4b2518149028b2` |
| Tnet.hk | [Public bulk-registration frontend](https://www.tnet.hk/panel/front/domain/bulkregister) | [Tnet main bundle](https://tnethk.oss-accelerate.aliyuncs.com/t/panel/umi.fceca900.js) | 6,609,911 / `ad5664c4ee6a029498f287c85c04b5c68b4b985bd69b62497f0dc997ff148f06` |

The CDN/object-storage URLs are **literal vendor-page script sources**, not guessed cloud object paths or account storage reads. Only explicitly published assets were fetched. No frontend JavaScript was executed. Public shell retrieval blocked redirects containing login/auth/session/ticket. Protected DNS-management pages themselves were not visited.

The main bundles explicitly map route `/domain/vdns` to chunk **429**, name `p__Panel__Domain__vdns`, JS hash `0c936c97`, suffix **`.async.js`**. Only this exact mapping was followed:

- [Now vdns component](https://cdn.nowcdn.cn/panel/p__Panel__Domain__vdns.0c936c97.async.js)
- [Eranet vdns component](https://eranet-com.oss-accelerate.aliyuncs.com/t/panel/p__Panel__Domain__vdns.0c936c97.async.js)
- [Tnet vdns component](https://tnethk.oss-accelerate.aliyuncs.com/t/panel/p__Panel__Domain__vdns.0c936c97.async.js)

All three were independently retrieved; each is **114,943 bytes**, SHA256 **`574539605942fc7c08612e6434ef9a3271a8dbc92d89da431420934bbba6f08e`**. Identical bytes establish publication of the same client component on each brand's linked asset surface, **not equivalent server behavior**.

The separate explicitly mapped chunk **2693**, `/domain/dns`, was also read from each brand: `p__Panel__Domain__dns.e123bb1d.async.js`, 22,055 bytes, SHA256 `bfbeb518b5d82c6d5c33397cabd5cfcce66366c7b41a8a8483b405a41d6ad299`. It lists DNS instances through `dns/fetch` → `/api/dns/index`, not resolution records; its pagination must not be mistaken for record-list evidence. Chunk-boundary extraction initially failed closed because the main bundle also maps CSS and uses `.async.js`; the actual suffix and JS-map boundary were read before any chunk URL was fetched. No guessed chunk variants were requested.

## 2. Actual action/base/response chain

These are source observations, not real responses or accepted requests. Source excerpts below omit minifier helper names where they only spread ordinary objects; native field names and methods are retained. Offsets are zero-based character offsets into the decoded UTF-8 source, not line numbers.

In **each** main bundle:

- Config module **29547**, offset approximately **183680**, sets `frontendApi: "/api"`.
- DNS service module **93988**, approximately **234191**, issues a relative GET to `/api/dns/DescribeRecordIndex?` plus serialized supplied payload.
- The `dns/DescribeRecordIndex` model effect calls that service and passes its result directly to the callback; it does not construct a separate row DTO.
- The vdns component's `We` list callback (approximately **85793**) stores the successful response directly with `Le(response)`; the table receives that state's **`Data`** array and **`Pagination`** object.
- The table reads row members `id`, `domain`, `host`, `type`, `value`, `ttl`, `state`, and additionally `mx`, `line`, `remark`. The existing native client DTO has the first seven plus remark, but not mx/line/Pagination. Matching common members is a useful binding clue, not an exhaustive native schema.

Resolving `/api/dns/DescribeRecordIndex` against each public shell's `www` origin yields **exactly** that brand's current independent-domain article's list origin/path/method. This is not an unrelated reseller URL. No `AccessInstanceID` literal occurred in the inspected main bundles, but its absence **does not prove** a distinct backend: the endpoint could support both session and HMAC authentication.

The component first reads `dns/DescribeDomainRecordInstance` and branches on returned **`Platform`** (`dnscom`, `powerdns`, other). That is actual multi-platform client evidence. No server implementation, auth-context dispatcher, or mapping from those platforms to the compiled independent-domain client's response was obtained. Thus the report distinguishes **current documented-route frontend semantics** from **accepted HMAC-context/legacy-route semantics**, without asserting either equality or separation as fact.

## 3. Numeric state and legal-setting evidence

The shared component's ordinary DNS-record table (approximately **101480–103400**, not its separate smart-analysis task-status table) renders:

```javascript
// Direct returned row field, without an observed State mapper.
label = translate(`dnspod.status.${row.state}`);
if (row.state === 0 || row.state === 2) {
  nextStatus = row.state === 0 ? "Disable" : "Enable";
  // Invokes the separate status action, not UpdateDomainRecord.
}
```

The advanced-search dropdown (approximately **60300–61200**) uses numeric **State** values **0, 2, 3, 4, 5** with those same status labels. All three separately inspected main bundles publish:

| Returned/search state | English label | Chinese label | Direct client implication |
| --- | --- | --- | --- |
| 0 | Normal | 正常 | Row offers Disable; enabled/normal UI interpretation |
| 2 | Pause | 暂停 / 暫停 | Row offers Enable; paused UI interpretation |
| 3 | Administrator Pause | 管理员暂停 | Not interchangeable with user-pause; no ordinary toggle rendered |
| 4 | In review | 待审核 | Not an enabled boolean |
| 5 | Unpass | 不通过 | Not an enabled boolean; redirect rejection may show remark |
| 1 | **No inspected status translation/filter option** | — | Meaning remains unknown; never infer enabled or disabled |

English state-label locations: Now offsets **656111–656234**; Eranet/Tnet **656027–656150**. Chinese translations corroborate Normal/Pause; inconsistent translations in other languages were not used to redefine states.

Actual status setter construction, component approximately **87382**, is:

```javascript
dispatch({
  type: "dns/SetDomainRecordStatus",
  payload: { Id: selectedIdOrIds, Status: "Enable" /* or "Disable" */ },
  callback: response => /* error check, success toast, list refresh */
});
```

Model → service maps this to **GET `/api/dns/SetDomainRecordStatus`**, with serialized payload. The labels explicitly say Enable/Pause parsing record success. **No `State` parameter is sent by this setter.** Numeric `State` in the search form is a list filter, not a mutation setter.

This proves first-party frontend intent for a status action on the current site's API namespace. It does **not** prove that it accepts independent-domain signed credentials, legal native State=0/1 mutation values, IDDomain requiredness, or preservation when State/Status is omitted from another method. The independently published API articles do not document this status method. Do not issue the setter or infer an accepted HMAC query from its public existence.

**Practical improvement:** “no official meaning for any state” is now too broad for the current documented www/lowercase getter. State 0 has meaningful route-bound first-party Normal/Disable evidence; state 2 is Pause/Enable. But neither a State=1 active gate nor automatic equivalence with the compiled api.now.cn/capital-Dns route follows. Any proposed narrow gate must state exactly which supported route/auth-response contract its evidence covers.

## 4. Per-ID preservation: useful request fields, no omit guarantee

The actual vdns save action (approximately **89819**) sends:

```javascript
// POST /api/dns/UpdateDomainRecord through the main service.
{
  Id: row.id,
  Domain: row.domain,
  Host: row.host === "" ? "@" : row.host,
  Type: row.type,
  Value: row.value,
  Mx: row.mx,
  Ttl: row.ttl,
  Line: row.line
}
```

**New positive evidence:** this first-party frontend explicitly forwards **Mx, Ttl, Line** from the selected returned row on ordinary per-ID save. It is not reconstructing a whole zone. The current articles instead document signed **GET** updates, and the compiled client sends GET plus IDDomain and optional application Remark. Do not transplant POST encoding, cookies, omitted IDDomain, or routing options into that native contract without evidence.

**Still not proved:** arbitrary/raw roundtrip or preservation-on-omit. Client editing can trim text, convert empty host to `@`, pick the final line-selector element, and default MX to 20 when changing type to MX. Ordinary update payload contains **neither State nor Remark**. An omitted field in a request is not evidence of the server's preservation rule.

`remark` is rendered as a tooltip for **state=5 redirect/forward rejection**, at approximately **101843**. This is evidence that returned remarks can contain operational diagnostics, **not** proof they are the independent API's user-editable Remark or that arbitrary remarks survive updates. The frontend does not raw-forward Remark in this save action; the compiled client's ownership-marker-only behavior remains unsafe as arbitrary remark preservation.

Additional independent help-article checks:

- [Now resolution management](https://help.now.cn/domain/resolve/23/), displayed 2023-09-05, expressly says existing records can edit host, type, **line**, DNS target. [Now mail-resolution guide](https://help.now.cn/domain/resolve/to_email/), 2020-08-27, prescribes separate MX records with priorities **10 and 20**.
- [Tnet resolution management](https://help.tnet.hk/domain/resolve/20221126120629/), 2022-11-26, independently describes line editing. [Tnet mail guide](https://help.tnet.hk/domain/resolve/20221123172436/), 2022-11-23, independently publishes MX priorities **10 and 20**.
- [Eranet domain help index](https://help.eranet.com/domain/) exposes the API/DDNS/template/DNSSEC articles inspected here, but no corresponding resolution-management/MX article. Its independently published frontend still explicitly handles Mx and Line; Now/Tnet prose was not assigned to Eranet.

These articles establish that settings matter to the products, not accepted native getter/setter mappings. Their instructions were read, never performed.

## 5. Inventory and acknowledgment: concrete new client behavior, still no real envelope

**Record-list pagination, not DNS-instance pagination:** vdns table pagination (approximately **92749**) dispatches `dns/DescribeRecordIndex` with **`currentPage`** and **`pageSize`**, combined with current filters and domain context. It consumes **Data/Pagination** directly. Search supports Host/Type/Line/Value/State and quickSearch/keyword; filters must not be treated as an authoritative complete snapshot.

The export button (approximately **93748**) calls the **same getter** with **`action: "export"`** plus current filters/domain context and exports returned Data. No complete-count comparison, server cap, stable-total check, or proof of unlimited export occurs in the inspected flow. Export columns include host/type/value/mx/ttl/stateText but not line/remark, so exported spreadsheets are not raw-preserving native fixtures.

This is new first-party request-key evidence for the **exact current documented URL**. It makes an unconditional assumption that every call to that URL always returns an uncapped full array less defensible. However, **the source alone neither proves actual truncation nor establishes that `currentPage/pageSize/action` work under independent HMAC authentication or capitalized routes**. Do not invent page completion semantics or call the export endpoint for acceptance.

The per-ID update callback (approximately **89800–90700**) treats falsy `response.error` as sufficient for a success toast. It requires no positive Id/RequestId/status/code and merely exits editing. The separate status callback similarly checks error and then refreshes the list. These are **weak client acknowledgments**, not official response fixtures or positive server contracts. The public sources did not provide a captured successful or HTTP-200-error JSON body. RequestId-only reseller examples remain a different unresolved contract; they were not imported.

## 6. Per-brand decision and remaining evidence

| Brand | Newly confirmed independently | Unresolved native contract / decision |
| --- | --- | --- |
| Now.cn | Current www/lowercase documented GET matches public frontend list; direct returned state 0 Normal/Disable, 2 Pause/Enable; frontend Mx/Ttl/Line save and record-list paging/export construction | Compiled api.now.cn/capital-Dns equivalence and HMAC-context schema remain unproved; state 1 unknown; signed status setter, GET omission preservation, raw Remark/MX/line, full inventory and positive ack unproved. Do not enable. |
| Eranet | Its own page/asset chain publishes the same direct state mapping and exact current documented GET URL; frontend per-ID fields/paging independently fetched | Same-origin route match is meaningful, but capital-Dns/HMAC context and Platform dispatch equivalence remain unproved; state 1 unknown; accepted signed setter/GET preservation/full inventory/ack unproved. Do not enable. |
| Tnet.hk | Its own page/asset chain independently publishes state mapping and current documented getter, plus independent line/MX help prose | Same native credential/case/dispatch and preservation/inventory/ack gaps; state 1 unknown. Do not enable. |

The [Now Android DDNS-X tutorial](https://help.now.cn/domain/resolve/20260518174947/), 2026-05-18, newly corroborates domain-level API Key onboarding and exact AccessInstanceID/AccessKeySecret labels but publishes no native state/response contract; its third-party app was not downloaded. The independently fetched [Tnet DDNS tutorial](https://help.tnet.hk/domain/resolve/20260407165549/), 2026-04-08, corroborates IPv4/IPv6 and domain-management API onboarding, not preservation/completeness. No tutorial was executed. The actually linked [Tnet VDNS support index](https://www.tnet.hk/support/vdns/) returned HTTP 404; no guessed successor paths were tried.

**Next evidence, not an instruction to contact operators or run acceptance:** a public official supported domain-HMAC example/schema tying the selected getter route's raw state and Pagination behavior to its authentication context; accepted status omission or a legal setter on that surface; a GET update contract covering selected A/AAAA settings; real-provenance positive write/error envelopes and ID lifecycle. Preserve the useful state-0/current-route and per-ID/paging discoveries without converting shared client intent into unsupported cross-brand or cross-authentication server guarantees.
