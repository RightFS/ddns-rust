# Aliyun ESA contract investigation — deferred, not implemented

Inspected **2026-11-09**. This is public-documentation/official-SDK research, not a supported-provider announcement. ESA remains unimplemented. No adapter, example, registry/module wiring, credential handling, signing implementation, or provider API requests were added. The parent authorized this isolated note after the original two-file implementation scope could not be proved safe.

## Decision and concrete blockers

**Follow-up qualification:** the [singleton-IPv4/unproxied review](<aliesa-narrow-scope-review.md>) found first-party Terraform partial-update intent and a complete legal setter mapping. IPv4-only combined-native records and unproxied DNS mode are documented; proxy port controls are inapplicable with proxy off. Do not demand illegal echoes of GET-only fields, invent `BizName=dns` or record `Status=enabled`. The remaining gap is a source-proven ordinary IPv4 payload/response and applicable settings/metadata preservation strategy, not categorical impossibility.

Do **not** count ESA as implemented or substitute ordinary AliDNS.

1. **Native address-record identity is contradictory.** Chinese Create/Get/List/Update schemas and the current official Go SDK describe **`A/AAAA`**, containing comma-separated addresses. API `Data.Value` descriptions require at least one IPv4 address. The user guide permits IPv4 or IPv6 addresses; English UpdateRecord prose separately names `A` and `AAAA`, but retains `A/AAAA` in its example and the IPv4 requirement. SDK model validation provides no enumerated type contract that resolves this. Splitting combined records into synthetic per-family records, guessing type from values, or replacing multi-address values could remove another address/family. This is insufficient evidence of a safe wire contract, not proof that IPv6 is impossible.
2. **Omitted-setting preservation is not documented.** `UpdateRecord` targets native RecordId, requires `Data`, and makes other fields optional. SDK nil-field exclusion proves request serialization, **not** that the server preserves omitted settings. GetRecord contains `Data.Tags` and `CustomPort`, which lack corresponding legal UpdateRecord model setters. Thus full JSON copying is not a proved legal lossless roundtrip either. Proxy/business/ports/control settings must not be reset by a guessed partial update.
3. **Read/write business enum mismatch.** Get/List/Create document `image_video`; Update documents `video_image`. Do not silently translate. Update AuthConf `Region`/`Version` descriptions are inverted relative to GetRecord. These CNAME fields would be outside an initial address-only scope, but illustrate why unvalidated copying is unsafe.

An explicitly approved **IPv4-only combined-record** capability might eventually be useful: require one exact native record, one literal IPv4 in `Data.Value`, no IPv6/other addresses, NS access, no proxy, no version management, no unsupported settings, and a proved complete legal update contract. That capability is not implemented or advertised. Narrowing alone does not prove omission preservation, and requires explicit family capability handling rather than silently claiming A and AAAA support.

## Proven request/read details

- API version **`2024-09-10`**; official SDK uses HTTPS, RPC style, root pathname `/`. Create/Update use POST. SDK endpoint selection is regional. Upstream uses `https://esa.cn-hangzhou.aliyuncs.com/`; no wider official region allowlist was established. A future initial scope should use only that fixed HTTPS endpoint/region, never a Web-editable URL or guessed endpoint list.
- Prospective constructor only, **not supplied**: `AliEsa::new(client, id, key, &options)`. Prospective env names: `ALIESA_ACCESS_KEY_ID`, `ALIESA_ACCESS_KEY_SECRET`. Require explicit `site_id`: positive signed-64-bit native integer represented losslessly as a decimal string, plus a declared scope mode. Do not infer the site or select the first result. A future RPC signer needs an independent Python golden and per-request registered secrets, including generated signature/full authentication/derived keys and their encoded forms.
- `GetSite(SiteId)` returns `SiteModel`: `SiteId`, `SiteName`, `AccessType` (`NS`/`CNAME`), `Status` (`pending`/`active`/`offline`/`moved`), and `VersionManagement`. Initial scope should require exact site ID/domain, `active`, explicit `NS`, and `VersionManagement=false`; missing/unknown values fail closed. Successful signed reads prove credential visibility, not an invented returned account-owner ID.
- `ListSites` returns `Sites`, `TotalCount`, `PageNumber`, `PageSize` (1–500). Any account-visible identity check must be exact, fully paginated and count/duplicate checked, without filtering out status/access-mode conflicts. Upstream's synthetic CNAME assumption for an explicit site ID is not acceptable proof.
- `GetRecord(RecordId)` returns `RecordModel`; ListRecords returns `Records`. Fields include `RecordId`, `SiteId`, `SiteName`, **FQDN `RecordName`** (e.g. `a.example.com`), `RecordType`, `Data.Value`, actual `Ttl`, `Proxied`, `BizName`, `Comment`, `AuthConf`, `RecordSourceType`, `HostPolicy`, `HttpPorts`, `HttpsPorts`, `CustomPort` and metadata. API name convention is FQDN; UI relative host entry is separate. A future adapter must declare `NameFormat::Fqdn`, not suffix stripping/Either.
- Documented TTL setting is **1 (automatic)** or **30–86400 seconds**. Read actual `Ttl`, never fabricate the desired value as observed TTL. Automatic 1 is not a known effective TTL in seconds. The user guide says proxy-enabled records cannot adjust TTL; do not invent proxy TTL/defaults or universal TTL writability.
- Create requires `SiteId`, FQDN `RecordName`, `Type`, `Ttl`, `Data`; returns `RecordId`/`RequestId`. Update requires `RecordId`/`Data`; documented success returns **only RequestId**, not RecordId. A future update must retain its selected ID and strictly postread identity/address/TTL/settings before reporting convergence. Acknowledgement is not global edge deployment proof. No writer retry or CAS guarantee was established.

## Ordinary ListRecords is explicitly incomplete

ListRecords documentation explicitly excludes edge-container, edge-function and Layer-4 acceleration DNS records. Even unfiltered, count-checked ListRecords pagination alone cannot prove hostname absence before would-create/create or all hostname conflicts.

Other documented inventories **exist**, so complete inventory is not claimed impossible:

| API | Request | Response |
| --- | --- | --- |
| `ListEdgeContainerRecords` | `SiteId`, `PageNumber`, `PageSize`; optional FQDN `RecordName`/`RecordMatchType` | `Records`, `TotalCount`, page metadata; FQDN/name/native ID |
| `ListEdgeRoutineRecords` | `SiteId`, `PageNumber`, `PageSize` (1–500); optional name matching | `Records`, `TotalCount`, page metadata |
| `ListTransportLayerApplications` | `SiteId`, `PageNumber`, `PageSize` (1–500); optional FQDN `RecordName`/`MatchType` | `Applications`, `TotalCount`, page metadata; `ApplicationId`, FQDN `RecordName`, rules/settings |

A future adapter must authenticate/read all relevant inventories before planning/writing; reject permissions, malformed/short/changing counts, invalid/repeated IDs, caps, conflicts and delegated NS ancestors. Feature unavailability/permission denial is not automatically a proven empty list. Refresh complete selection/absence immediately before writes; no CAS means one writer. Ancillary inventory/status mapping was not implemented/tested here.

## Evidence needed to unblock

1. Official unambiguous native types and per-family identity/read/write semantics, resolving IPv6-only support versus the IPv4 requirement; alternatively approve explicit singleton-IPv4 combined-record capability.
2. Server guarantee that omitted UpdateRecord fields, including nested Data, stay unchanged; **or** a complete legal lossless setter mapping including `Data.Tags`, `CustomPort`, ports/business settings. Cover missing/null/empty/default/masked/unknown fields and prove non-applicable settings cannot reset in any narrow scope.
3. Resolve `image_video`/`video_image` before that business mode, and AuthConf Region/Version before CNAME scope.
4. Verify excluded-record inventories, pagination/status/permission contracts, site/access/version proof. Then add localhost Axum tests for fail-before-noop/dry-run/write, fresh prewrite races and strict postreads; generated-signature credential-redaction and independent signer goldens must be tested.

No always-failing “implemented” adapter or misleading disabled example was substituted for these proofs.

## Official sources

- [GetSite](https://help.aliyun.com/zh/edge-security-acceleration/esa/api-esa-2024-09-10-getsite), [ListSites](https://help.aliyun.com/zh/edge-security-acceleration/esa/api-esa-2024-09-10-listsites).
- [GetRecord](https://help.aliyun.com/zh/edge-security-acceleration/esa/api-esa-2024-09-10-getrecord), [ListRecords](https://help.aliyun.com/zh/edge-security-acceleration/esa/api-esa-2024-09-10-listrecords), [CreateRecord](https://help.aliyun.com/zh/edge-security-acceleration/esa/api-esa-2024-09-10-createrecord), [Chinese UpdateRecord](https://help.aliyun.com/zh/edge-security-acceleration/esa/api-esa-2024-09-10-updaterecord), [English UpdateRecord](https://www.alibabacloud.com/help/en/edge-security-acceleration/esa/api-esa-2024-09-10-updaterecord).
- [DNS type/parameter guide](https://help.aliyun.com/zh/edge-security-acceleration/esa/user-guide/introduction-of-dns-related-parameters), [DNS record management](https://help.aliyun.com/zh/edge-security-acceleration/esa/user-guide/manage-dns-records-new).
- [ListEdgeContainerRecords](https://help.aliyun.com/zh/edge-security-acceleration/esa/api-esa-2024-09-10-listedgecontainerrecords), [ListEdgeRoutineRecords](https://help.aliyun.com/zh/edge-security-acceleration/esa/api-esa-2024-09-10-listedgeroutinerecords), [ListTransportLayerApplications](https://help.aliyun.com/zh/edge-security-acceleration/esa/api-esa-2024-09-10-listtransportlayerapplications).
- Official Go SDK inspected master revision `920db6e77c7f581336f97e41fb223423a17fbae6`: [operations](https://github.com/aliyun/alibabacloud-go-sdk/blob/920db6e77c7f581336f97e41fb223423a17fbae6/esa-20240910/client/client.go), [UpdateRecord request](https://github.com/aliyun/alibabacloud-go-sdk/blob/920db6e77c7f581336f97e41fb223423a17fbae6/esa-20240910/client/update_record_request_model.go), [GetRecord response](https://github.com/aliyun/alibabacloud-go-sdk/blob/920db6e77c7f581336f97e41fb223423a17fbae6/esa-20240910/client/get_record_response_body_model.go), [CreateRecord request](https://github.com/aliyun/alibabacloud-go-sdk/blob/920db6e77c7f581336f97e41fb223423a17fbae6/esa-20240910/client/create_record_request_model.go).

Local references read: [common.rs](../src/providers/common.rs), [alidns.rs](../src/providers/alidns.rs), upstream [aliesa.go](../../ddns-go/dns/aliesa.go). Upstream combined-type writes, first-result selection, fabricated site access and acknowledgement are not imported as safety proof.

## Validation and limits

Only public documentation/public SDK sources were fetched: **zero live provider API calls and zero provider credentials**. No Rust code changed; no ESA mock tests, signature golden or new adapter compilation was performed. Previous suite counts are not validation of ESA. Only this parent-authorized note changed; shared code, Cargo, other docs and examples were not edited.
