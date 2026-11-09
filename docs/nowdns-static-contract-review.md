# NowDNS v1.0.0 — static independent-domain contract review

Research date: 2026-11-09. **This improves first-party client evidence, but does not yet establish a safe complete-snapshot, all-active per-native-ID adapter.** No provider/catalog/Cargo/shared changes, repository builds/tests, credentials, account inventory, DNS lookups or live API operations were performed. The downloaded binary and service script were never executed. This note is the only documentation/source deliverable; optional inert analysis artifacts are under `target/nowdns-static-*`.

## Provenance and methods

- Read the last follow-up in [registrar contract notes](<registrar-contract-notes.md>); independently fetched the exact [official tutorial](https://help.now.cn/domain/resolve/20260827165148/), [its directly linked Linux ARM64 ZIP](https://www.now.cn/download/nowdns/releases/v1.0.0/builds/package/nowdns-v1.0.0-linux-arm64.zip), [official manifest](https://www.now.cn/download/nowdns/manifest.json), and [current Now independent-domain API article](https://help.now.cn/domain/resolve/20260310102214/). No guessed endpoints, login, brand probing, reseller requests or other archives were fetched.
- Before using binary evidence, verified ZIP length **5,207,009 bytes** and SHA256 **`987dce5e7be068d9b0aed6cb20dbd7f894f6bb8f874b3f14626333b765762c36`**, matching tutorial and manifest. Manifest stable v1.0.0 publication is `2026-08-28T07:54:31.8423371Z`; its six assets are binary ZIPs, not source/PHP SDKs.
- Python standard-library `urllib`, `hashlib`, `zipfile`, `struct` inspected the archive/ELF. ZIP member names contain **backslashes**, even for this Linux package. A first basename assertion failed before any member was written; separator-aware selection fixed it. No `extractall`, arbitrary extraction paths, downloaded-program execution or installation. Selected only the member with normalized basename `nowdns`, then wrote to the resolved fixed [inert ELF artifact](<../target/nowdns-static-linux-arm64.elf>) with mode **0600**, not executable.
- Exactly four ZIP members: binary (12,779,682 bytes), example YAML (990), service script (6,530), user guide (22,742). ELF SHA256 **`c7165317b6a9657079e32ca0265febf749958ca40320cbce0fca58527466e7f3`**. Embedded metadata reports `go1.26.5`, Linux ARM64, `nowdns/cmd/nowdns`, revision `d5bcd647a8268f532f890394e173daff7a6d6907`, commit time `2026-08-28T07:22:43Z`, **modified=true**. This identifies the artifact, not a published/verified source repository.
- Installed `go tool nm` and `GOTOOLCHAIN=local go tool objdump -s ...` failed: stripped ELF has **no symbol section**. Installed `/usr/bin/objdump` succeeds on explicit address ranges; no external tools installed. Recovered function names/entries from `.gopclntab`, reflection types/struct tags from `.typelink` and `.rodata`. The pclntab textStart is zero here; entries were correctly based at ELF `.text` **0x11000**. [Annotated disassembly](<../target/nowdns-static-disassembly.txt>) maps branch targets to Go functions and data addresses to adjacent bytes. Broad adjacent-byte comments are navigation aids, **not inferred string lengths/semantics**; conclusions use instruction argument lengths, call sites and exact type layouts.

**High client confidence** below means exact construction/decoder behavior recovered from the official artifact; it is not live server acceptance, an exhaustive server schema, or cross-brand server equivalence.

## Confirmed first-party CLIENT behavior

### Fixed endpoints and domain-scoped association

Actual brand constructor → shared `todaynic.New` call flow, not just strings:

| Constructor / ELF VA | Compiled base |
| --- | --- |
| `nowcn.New`, **0x2e19a0** | `https://api.now.cn` |
| `eranet.New`, **0x2dbcd0** | `https://www.eranet.com` |
| `tnethk.New`, **0x2e9d90** | `https://www.tnet.hk` |

`todaynic.Provider.call`, **0x2d9850**, generates signed **GET** through `net/http.NewRequestWithContext`, using base + supplied route + `?` + signed query. Shared routes actually used:

```text
/api/Dns/DescribeRecordIndex
/api/Dns/AddDomainRecord
/api/Dns/UpdateDomainRecord
/api/Dns/DeleteDomainRecord
```

Tutorial per-brand selection/domain-ID-secret onboarding, embedded frontend `AccessInstanceID`/`Secret` labels, matching current article methods and constructor flow associate this with intended **domain-scoped independent-domain use**, rather than borrowing reseller examples.

**Now's current prose remains contradictory:** it specifies `https://www.now.cn`, lowercase `/api/dns/`, and HMAC key `AccessKeySecret` without suffix. The newer official client explicitly uses `api.now.cn`, `/api/Dns/`, and `secret&`. This supersedes “only copied Go/reseller evidence exists” for these client choices, **not** proof of live compatibility, route aliases, redirects or interchangeable deployments. Do not probe/fallback. Now's official shared brand constructors establish client intent, not independently published Eranet/Tnet server response/preservation authority.

### Exact signing

Recovered `todaynic.(*Provider).sign`, **0x2db130**, and `percentEncode`, **0x2db060**:

1. Set `AccessInstanceID=Provider.id`, `SignatureMethod=HMAC-SHA1`.
2. Set `SignatureNonce` to decimal **`now.UnixNano()`** (not a random UUID); UTC Timestamp uses `2006-01-02T15:04:05Z`. A future adapter should use a genuinely fresh nonce; UnixNano is not a collision/replay guarantee.
3. Collect keys **except exact `Signature`**, `sort.Strings`, join encoded `key=value` pairs with `&`.
4. Percent encoding uses URL query escaping, then `+`→`%20`, `*`→`%2A`, `%7E`→`~`. Empty input remains empty.
5. `StringToSign = method + "&" + percentEncode("/") + "&" + percentEncode(canonicalQuery)`; actual call passes `GET`. **The DNS route/base is not the signed path component.**
6. Key is exact **`Provider.secret + "&"`**. At **0x2db70c–0x2db74c**, secret at Provider struct offset **0x20** is loaded, concatenated with literal one-byte `&`, converted to bytes, then passed to `crypto/hmac.New`. Hash-function value **0x73ffe0** points to **0x1902b0 `crypto/sha1.New`**. This is exact data flow, not an ambiguous ampersand near a generic HMAC call.
7. Standard padded Base64 digest → Signature; re-sort and encode final query. Global **0xc33e68** loaded for encoding is initialized in `encoding/base64.init` (**0xffd10**) with the standard alphabet and `=` padding, not URL-safe/raw Base64.

Thus `secret&` is now **first-party independent-domain CLIENT evidence**, stronger than the older reseller-only citation. No server signature vector was requested/validated.

### List request and DTO

`ListRecords`, **0x2d83b0**, sets only these method-specific string parameters before common signing fields:

```text
Domain   = normalized supplied zone
IDDomain = Provider.id     # same credential ID as AccessInstanceID
```

It calls `/api/Dns/DescribeRecordIndex` **once**, then iterates that response's `Data` slice. No page/current/pageSize/offset/limit/Host/Type request keys, pagination loop, total comparison or completion check occur in this function. `IDDomain` is actual client behavior; requiredness/server meaning is not separately documented. Do not invent a second credential or domain-ID discovery API.

Exact recovered Go reflection model (normalized display names; **decoder definitions, NOT server fixtures**):

```go
type baseResult struct {
    RequestId string   `json:"RequestId"`
    Id        resultID `json:"Id"`
    Error     string   `json:"error"`
}
type listResponse struct {
    baseResult
    Data []record `json:"Data"`
}
type writeResponse struct { baseResult }
type record struct {
    ID     int    `json:"id"`
    Domain string `json:"domain"`
    Host   string `json:"host"`
    Type   string `json:"type"`
    Value  string `json:"value"`
    State  int    `json:"state"`
    TTL    int    `json:"ttl"`
    Remark string `json:"remark"`
}
```

Type addresses: listResponse **0x6305a0**, baseResult **0x63fa80**, record **0x662a20**, writeResponse **0x615740**. String-backed `resultID.UnmarshalJSON` (**0x2dac60**) tries JSON string, then **int64** with decimal formatting. Inventory `id` is ordinary Go `int` (64-bit here), not the custom string-or-number decoder. No ID stability/lifecycle, positivity or string-inventory-ID compatibility follows.

**No Pagination/total/count/cap/MX/line/updated-time fields in these response types.** Ordinary `encoding/json.Unmarshal` ignores unknown members and zero-defaults absent members. This decoder does not prove servers lack omitted controls, or that missing/empty `Data` is a complete empty zone. Todaynic reseller `Data/Pagination` fixtures must still not be imported.

### Update fields, state and TTL

`UpdateRecord`, **0x2d90f0**, validates native ID and A/AAAA mutation, then sends:

```text
Id, Domain, IDDomain, Host, Type, Value, Ttl
Remark = "nowdns:" + ownershipMarker    # only if marker nonempty
```

`Id` is supplied nonempty trimmed record ID; `IDDomain` is credential `Provider.id`. This is concrete per-ID full-field GET update, **not** the article's contradictory Host-only sample. Decimal TTL input is used, except zero becomes **600** (**0x2d940c–0x2d9424**). No State/Mx/line/routing/updated-time/conditional-revision parameter. Optional Remark is an application ownership marker, **not arbitrary remark roundtrip**.

`record.toProviderRecord`, **0x2dada0**, decimalizes numeric ID, qualifies Host against supplied zone, carries nonzero TTL but substitutes **600 for zero**, extracts only `nowdns:`-prefixed remarks into the marker, and **does not propagate or filter native State**. Native Domain is not used to validate equality with requested zone in this converter. Its provider record has ID/name/type/value/TTL/marker, not native activation/MX/line controls.

This establishes intended A/AAAA use/encoding, but not numeric State meanings or a provably all-active snapshot. Defaults/discarded metadata are **not safe preservation rules** to copy. No server reset on omitted State/Remark is asserted; preservation-on-omit remains unproved.

### Success/error handling

`call` reads at most **10 MiB + 1**, rejects bodies over **10 MiB**, non-2xx status, JSON decode failure, and nonempty decoded `error` string. It then optionally decodes the method DTO.

- Update requests no output DTO and requires **no positive RequestId/Id/acknowledgment**. Valid JSON objects with missing `error` are accepted by this client's control flow: observed client permissiveness, **not authoritative success**.
- Numeric/object errors or alternate envelopes are not established by its string field. No live success/error body was captured.
- The body limit is a client bound, not a server record ceiling/completeness guarantee.

## Purely synthetic signing golden — NOT live/vendor acceptance

Offline arithmetic reproduces statically recovered list/signing rules with dummy values. Calculated with Python standard-library percent encoding/HMAC-SHA1/Base64, without running the downloaded binary or any API. No matching response fixture exists.

Credential ID `testid`, secret `testsecret`, domain `example.com`; fixed time `2026-08-28T07:22:43Z` with zero fractional seconds gives nonce `1787901763000000000`.

Canonical query **without Signature**:

```text
AccessInstanceID=testid&Domain=example.com&IDDomain=testid&SignatureMethod=HMAC-SHA1&SignatureNonce=1787901763000000000&Timestamp=2026-08-28T07%3A22%3A43Z
```

StringToSign:

```text
GET&%2F&AccessInstanceID%3Dtestid%26Domain%3Dexample.com%26IDDomain%3Dtestid%26SignatureMethod%3DHMAC-SHA1%26SignatureNonce%3D1787901763000000000%26Timestamp%3D2026-08-28T07%253A22%253A43Z
```

Key bytes: ASCII `testsecret&`. Base64 HMAC-SHA1:

```text
KpGrkqBOu4Se1nq2upWakevHSDk=
```

Final query signature encoding: `KpGrkqBOu4Se1nq2upWakevHSDk%3D`. Synthetic escaping check: `a b+*~/%` → `a%20b%2B%2A~%2F%25`. These are prospective local signer test expectations only, not vendor-published/live vectors or accepted-route proof.

## What improved; remaining adapter gates

A genuine newer official domain-scoped client now corroborates legacy Now base/case, exact suffix, AccessInstanceID, undocumented IDDomain, full-field per-ID update, concrete decoder fields and raw State/TTL/Remark. Lack of public PHP alone is **no longer** the signing evidence gap. Static DTO evidence materially narrows fixture requests; it cannot supply actual server responses.

Still obtain **each target brand's independently supported domain-scoped** contract/fixtures proving:

1. One currently supported HTTPS base/route case/signing choice, with no variant probing; IDDomain requiredness and relationship to AccessInstanceID.
2. Complete unfiltered inventory: real envelope and count/cap or pagination request/completion rules. **An official client reading one Data array is not proof of all records.**
3. Native state meanings and a representable all-active gate; raw TTL validity and selected A/AAAA update preservation, including omitted State/line/MX/Remark behavior. Unrelated records remain untouched; no inferred defaults/state filtering.
4. Positive write acknowledgment and error shapes (including HTTP-200 errors), native ID lifecycle and authoritative readback.

Shared brand constructors prove official **client intent**, not Eranet/Tnet server equivalence to Now. No behavior was transplanted, no adapter enabled, no whole-zone write proposed. When evidence permits a real narrow all-active A/AAAA per-ID adapter, unsupported controls should reject only affected snapshots/configurations, not become an always-failing placeholder.
