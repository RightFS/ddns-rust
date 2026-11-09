# Dynadot REST v2 — focused second opinion, still deferred

Inspected **2026-11-09**. Read-only public-documentation research, not an adapter implementation or server validation. Only this new note is authored; the existing [contract notes](<dynadot-contract-notes.md>) and source remain unchanged. Dynadot remains `implemented = false` through the [registry's unimplemented fallback](<../src/providers/registry.rs#L306-L312>). The supplied baseline (558 Rust, 32 VM, 24 configurations, 41 HTTP passes; 24/29 rollout) was **not rerun** here.

## Sources and evidence pin

- **S1 — official regional REST overview:** [dynadot.com.cn/domain/api-document](https://dynadot.com.cn/domain/api-document), HTTP 200. Also retrieved [the ddot.in regional overview](https://www.ddot.in/domain/api-document), HTTP 200, with the same signing/DELETE/Beta guidance. These public pages identify Dynadot, point to `api.dynadot.com`, and backlink to API-settings help on `www.dynadot.com`. No login, challenge solving, credentials, authenticated API call, or sandbox DNS execution was performed.
- **S2 — official regional frontend machine documentation:** [v2 command-data URL](https://dynadot.com.cn/dynadot-vue-api/dynadot-service/api-document-data-api?command=get_api_command_info_data&apiVersion=2.0.0&lang=en). Parsed the entire JSON response in memory and extracted `domain_info`, `get_dns`, `set_dns`, `remove_dns`, including parameters, error lists and demos. Raw response length **1,946,687 bytes**; raw-byte SHA-256 **`73bf526aac197374e9379c3c26139b43198276f15757e308f14760fbdd849140`**; HTTP `Date: Mon, 09 Nov 2026 12:11:20 GMT`; `Cache-Control: private, no-cache, no-store, max-age=0`. This is a dated retrieval/content fingerprint, **not** a provider release date, immutable URL, preserved full snapshot, or confirmation of dated live-server behavior.
- **S3 — GitHub public metadata:** [Dynadot user](https://api.github.com/users/dynadot), [its repositories](https://api.github.com/users/dynadot/repos?per_page=100), [SDK search](https://api.github.com/search/repositories?q=dynadot+sdk&per_page=50), [RESTful search](https://api.github.com/search/repositories?q=dynadot+restful&per_page=50), and [name search](https://api.github.com/search/repositories?q=dynadot+in:name&per_page=100). GitHub metadata requests only, not Dynadot cloud requests.

General web search was unavailable because the configured service had no API key; no credential setup was attempted. A ddot.in command-data fetch returned non-JSON and was not interpreted as schema or worked around. The successful `.cn` command-data fetch is the evidence. Retrieval failures do not prove an SDK absent.

## 1. No company-proven REST v2 SDK found

The GitHub account named `Dynadot` has `type: User`, `company: null`, an empty `blog`, and zero public repositories/gists. Its name alone does **not** establish Dynadot ownership. The inspected regional overview supplies first-party signing code but no retrieved SDK/GitHub backlink establishing a maintained repository.

The exact SDK search returned [jeskesolutions/dynadot-go-api](https://github.com/jeskesolutions/dynadot-go-api), described as a Go SDK for **v1.x**, owned by `jeskesolutions`. The RESTful search returned [Eyalm321/dynadot-mcp](https://github.com/Eyalm321/dynadot-mcp), described as a REST **v2** MCP server, owned by `Eyalm321`. Neither an owner name nor a repository's Dynadot description is company provenance. No actual Dynadot-site backlink/company-maintainer evidence was established for either; neither resolves server behavior. Other registrar integrations and third-party company-profile material in the name search do not become first-party schemas.

**Conclusion:** no fresh first-party SDK or dated server-behavior example analogous to the requested Namecheap evidence was established. This is a bounded negative search result, not a claim that none exists anywhere.

### Bounded third-party fixture check

Inspected the MCP's [complete tree](https://api.github.com/repos/Eyalm321/dynadot-mcp/git/trees/main?recursive=1), commit **`1857c1a130da6904e6c3fb95e27b746f7dbd7beb`**, and pinned [README](https://raw.githubusercontent.com/Eyalm321/dynadot-mcp/1857c1a130da6904e6c3fb95e27b746f7dbd7beb/README.md), [domain tests](https://raw.githubusercontent.com/Eyalm321/dynadot-mcp/1857c1a130da6904e6c3fb95e27b746f7dbd7beb/src/__tests__/tools/domains.test.ts), and [client tests](https://raw.githubusercontent.com/Eyalm321/dynadot-mcp/1857c1a130da6904e6c3fb95e27b746f7dbd7beb/src/__tests__/client.test.ts). Contrary to the repository metadata's v2 description, its README says v3 `api3.json`; domain-info/GET DNS/SET DNS tests call the legacy client (`get_dns`, `set_dns2`). These tests use `vi.fn().mockResolvedValue({success:true})`, not recorded DNS-mode wire responses. Client tests stub global fetch; the v2 test is only unsigned appraisal with a synthetic `{value:100}` response. A mocked error says `X-Signature header not entered`, but neither the tests nor README give recorded-response provenance for it; it cannot establish server behavior. No origin-documented captured complete-DNS response/addition/removal fixture was found in this bounded inspection. No SDK code or tests were executed.


## 2. DELETE JSON is a defensible command-specific exception

S1's Body section first says bodies are “not typically” used for GET/DELETE, then states categorically that DELETE has no request body. S2's **specific** `remove_dns` independently gives:

```json
{
  "commandName": "remove_dns",
  "apiVersion": "v2",
  "requireSignature": false,
  "requestDemoJson": {
    "requestHeader": {
      "Method": "DELETE",
      "URL": "https://api.dynadot.com/restful/v2/domains/{domain_name}/records",
      "Content-Type": "application/json",
      "Accept": "application/json",
      "Authorization": "Bearer "
    },
    "requestBody": {
      "dns_main_list": [{"record_type":"String","record_value1":"String","record_value2":"String"}],
      "dns_sub_list": [{"sub_host":"String","record_type":"String","record_value1":"String","record_value2":"String"}]
    }
  }
}
```

Its parameter prose says **“List of main DNS records to remove.”** and **“List of sub DNS records to remove.”** Its response parameters say removal was executed successfully and the specified number of entries have been deleted, with integer `main_record_removed_count` / `sub_record_removed_count`. These mutually supporting command details are stronger than an accidentally nonempty generic demo alone.

**Assessment:** treating this as the more-specific normative exception is reasonable. Generic DELETE/no-body language **alone** need not be an irreconcilable implementation blocker. The exception has concrete provider-published command evidence, not a safe-default guess. This does not show server acceptance, tuple matching or defaults. `String` values above are schema placeholders, not DNS fixtures or request values.

Neither the retrieved parameter prose nor error list explicitly says whether omitted tuple fields are wildcards, defaults or ignored; whether matching compares all tuple members; or whether duplicate exact tuples remove one versus all matches. Thus “exact-value removal” in the earlier notes should be read as **record-value-bearing removal capability**, not fully proven exact-tuple semantics.

## 3. Actual removal gaps

S2 calls `record_value2` optional `String` and labels it **“unused”** for A/AAAA in the record-type tables. Those tables give ordinary single-value examples, not a complete observed read/remove cycle. The removal demo includes a `record_value2: "String"` placeholder for every type.

- Optionality/“unused” do not establish equivalence of **absent**, **empty string**, and **JSON null** in reads or matching. `null` is not documented as an accepted String value.
- Echoing an observed second value, inventing an empty one, or omitting one does not prove exact removal. Rejecting nonempty/null observations could narrow scope but still does not establish matching for absent/empty cases.
- Count descriptions and the 200 demo support **completed deletion acknowledgement**, not just queueing. Both counts are marked optional; an omitted other-kind count cannot silently become zero. Requiring explicit counts is possible, but post-write rejection cannot repair collateral deletion.

**Critical gap:** first-party accepted-payload/matching specification or redacted controlled A/AAAA replacement evidence, including unused-field normalization and duplicate handling.

## 4. Newly isolated additive-operation acceptance gaps

S2's `set_dns` parameter/error metadata exposes additional concrete questions:

| Published detail | Consequence / remaining question |
| --- | --- |
| `dns_main_list` and `dns_sub_list` are optional lists | The command's 400 errors nevertheless include **“The required parameter dns_main_list is missing.”** Subrecord-only additive POST acceptance without a main list is unproven. An empty main list is not demonstrated as accepted/preserving either. Do not satisfy this by copying unrelated apex records. |
| Additive Boolean: **“Add DNS records to current settings, default is false.”** | Positive evidence of additive intent, not append-versus-replace behavior for another IP at the **same** host/type, nor a complete non-record-settings preservation contract. |
| 400: **“The same sub host cannot be entered twice and must be unique.”** | Scope is unspecified: submitted list, current plus submitted inventory, specific family, or all subrecords. Does **not** prove add-before-remove impossible; does leave same-host coexistence unproven. |
| 429: **“Cannot add DNS for [domain_name]. The Dns Settings reached the upper limit.”** and equivalent subdomain limit | Evidence that additive capacity checks exist; not evidence of same-host coexistence or untouched settings. |
| `ttl`: optional Long, **“Time to live for DNS records, default is 86400.”** | GET exposes zone-level optional String `ttl`. Supplying the equal observed numeric TTL avoids relying on omission, but accepted mapping/additive behavior need evidence. Omission is **not** proven preserve-current. |
| Empty response parameters; 200 demo only `{"code":200,"message":"Success"}` | No changed-record count, resulting inventory, operation ID or specific synchronous-application prose. General 2xx means received/accepted. Complete readback is necessary; the demo alone does not prove synchronous successful addition. |

The A/AAAA conflict tables also list apex `aname`, `forward`, `stealth`, and subrecord `forward`, beyond CNAME. These are material target conflicts, not unrelated records safely ignored at that target.

**Critical gap:** prove that additive `true` permits old/new IP coexistence at the same target without replacing unrelated rows, accepts the chosen single-kind payload, and leaves global TTL and mail/forwarding/settings untouched. “Current settings” documents intent, not all missing preservation semantics. Readback is necessary but cannot retrospectively prevent a destructive side effect.

## 5. Useful read schema, but still no active-DNS fixture

Fresh S2 still supplies:

- Required `domain_info` Object with optional identity and Boolean `locked`, `disabled`, `udrp_locked`, `registrant_unverified`, `hold`. Optional String `status` explicitly lists **`active`** among examples: genuine recognized-state evidence, although the demo's `"status"` is a placeholder.
- Domain info and records expose `glue_info`, supported `glue_type` **`dns`**, optional main/sub lists and optional **String** `ttl`. GET records requires the `glue_info` Object; the command has no request parameters or documented pagination.
- Optional nameservers, advertising/forwarding fields, `email_forward_type` with `mtype_none`, `mtype_forward`, `mtype_mx`, mail exchanges and aliases. Nested mail prose refers to `forward_type = "mx"` / `"forward"`, unlike the dedicated email-mode vocabulary. This is a further setting-description inconsistency, not evidence of a lossless round trip.
- The retrieved 200 JSON demos for domain info/records remain **`REGISTRAR_PARKING`**, `with_ads: "Yes"`. They contain no complete active-DNS arrays, empty-array cases, actual DNS TTL or inactive-email/settings representations. None is fabricated here from parking samples.

Optional lists cannot mean missing equals empty. Conversely, optionality alone need not block a narrow adapter that requires **both lists present** and rejects omission. The remaining issue is provider evidence of complete accepted active-DNS inventory and preserved settings. No documented pagination is supporting context, not a guarantee against undocumented truncation.

## 6. Parseable differences versus critical unresolved contracts

**Not intrinsically universal blockers:**

- Boolean schema versus `"Yes"` demos permits a bounded parser (actual booleans and deliberately enumerated Yes/No spellings), rather than refusing all v2 responses. The demo proves title-case `Yes`; `No` as inverse or additional casing is explicit parser policy, not a demonstrated active-DNS fixture. Reject missing/null/numeric/unknown values and conflicting alias/duplicate representations, rather than selecting whichever wins. No parser fixtures/tests were completed here.
- Lowercase mode tokens versus uppercase parking tokens permits finite spelling mapping. Exact `dns` already has parameter support. Do not invent an active `DNS` sample or accept arbitrary unknown modes by lowercasing. Conflicting/missing modes still reject.
- v1 camelCase/array/list-name discrepancies do not block an isolated v2 adapter with no v1 reads/fallback.
- Generic DELETE body guidance may yield to the concrete command exception above.
- Beta is a scope/product requirement, not a schema impossibility: require explicit **noncritical v2 Beta opt-in**, never stable-production marketing or silent enabling.

**Still unresolved / potentially critical:**

- **Header selection:** S1 explicitly says apply the HMAC as **`X-Signature`**, and first-party Python prints that name. S2 signed-command demos use **`Signature`**. Strong evidence favors the normative `X-Signature` instruction, but accepted aliases/dual-header precedence are not established. Do not send both automatically, retry another header or claim SDK-confirmed acceptance. `remove_dns` additionally has `requireSignature: false` versus generic transactional signing: plausible command exception, not confirmed server behavior.
- **Destructive matching and additive acceptance/preservation:** sections 3–4, especially same-host coexistence, unused second-value semantics, required-apex-list contradiction, TTL and mail/settings preservation.
- **Complete active-DNS inventory/state:** section 5; missing flags are not false, optional lists are not empty, and parking placeholders are not operational DNS evidence.

## Decision / minimum next evidence

**No narrow real adapter is unblocked.** This second opinion reduces overbroad objections (generic DELETE, finite flag/mode parsing, irrelevant v1 mismatches) and isolates destructive-operation contracts plus a new additive acceptance question. It does not claim impossibility or hide uncertainty behind optional/default handling.

Resume only with a company-proven maintained SDK or explicit first-party clarification/redacted controlled examples establishing: accepted signing header; complete active-domain/DNS state with real TTL/inactive settings; sub-only additive payload semantics; old/new same-host coexistence; untouched unrelated DNS/mail/settings/global TTL; and exact removal matching/default normalization/counts. Provider-issued examples or user-supplied archived/sandbox evidence are suitable. This task requested no credentials, support emails, logins or live SDK execution. Then implement and independently validate localhost tests before a registry change. No completed mock, Cargo, VM, configuration or HTTP-test claims are made here.
