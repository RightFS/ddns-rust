# ESA singleton-IPv4 narrow-scope second opinion

Inspected **2026-11-09** using public first-party source and documentation only. This is a review, not an adapter or a supported-provider announcement. The earlier [contract note](<aliesa-contract-notes.md>) is left unchanged. Only this new review was written; no source, Cargo, credentials, vendor API reads/writes, or vendor acceptance-test execution.

## Result

**The requested high-confidence safe update contract is not yet proved.** However, the old deferral should be narrowed, not treated as sacred: a complete legal setter mapping exists for the ordinary mutable fields, and several old concerns are irrelevant to an explicitly unproxied singleton-IPv4 mode. Requiring illegal echoes of every GET field is the wrong unblock criterion.

The new evidence is an actual first-party Terraform resource and acceptance-test source, pinned to **`aliyun/terraform-provider-alicloud` commit `88ba5950ab0af3bd2c5f29bc6528e6a2acb3e85e`**. The current resource has moved under `alicloud/service/esa/`; the old master path returns 404, which is not evidence that ESA is unsupported. Release **v1.270.0** also contains the resource at its old path. Its documentation says available since **v1.240.0**. All these implementations call ESA API **`2024-09-10`**, not ordinary AliDNS.

## First-party provenance

- [Current pinned Terraform resource](https://github.com/aliyun/terraform-provider-alicloud/blob/88ba5950ab0af3bd2c5f29bc6528e6a2acb3e85e/alicloud/service/esa/resource_alicloud_esa_record.go).
- [Current pinned acceptance-test source](https://github.com/aliyun/terraform-provider-alicloud/blob/88ba5950ab0af3bd2c5f29bc6528e6a2acb3e85e/alicloud/service/esa/resource_alicloud_esa_record_test.go).
- [Current pinned read service](https://github.com/aliyun/terraform-provider-alicloud/blob/88ba5950ab0af3bd2c5f29bc6528e6a2acb3e85e/alicloud/service/esa/service.go): `DescribeEsaRecord` calls `GetRecord(RecordId)` and returns `RecordModel` directly; it does not manufacture an ordinary-record fixture or enabled status.
- [Current pinned Terraform resource documentation](https://github.com/aliyun/terraform-provider-alicloud/blob/88ba5950ab0af3bd2c5f29bc6528e6a2acb3e85e/website/docs/r/esa_record.html.markdown).
- [v1.270.0 resource](https://github.com/aliyun/terraform-provider-alicloud/blob/v1.270.0/alicloud/resource_alicloud_esa_record.go), [v1.270.0 tests](https://github.com/aliyun/terraform-provider-alicloud/blob/v1.270.0/alicloud/resource_alicloud_esa_record_test.go).
- Official Go SDK revision **`920db6e77c7f581336f97e41fb223423a17fbae6`**: [Update request](https://github.com/aliyun/alibabacloud-go-sdk/blob/920db6e77c7f581336f97e41fb223423a17fbae6/esa-20240910/client/update_record_request_model.go), [Get response](https://github.com/aliyun/alibabacloud-go-sdk/blob/920db6e77c7f581336f97e41fb223423a17fbae6/esa-20240910/client/get_record_response_body_model.go), [module](https://github.com/aliyun/alibabacloud-go-sdk/blob/920db6e77c7f581336f97e41fb223423a17fbae6/esa-20240910/go.mod). Module identity is `github.com/alibabacloud-go/esa-20240910/v3`. The master Update request was also fetched and still has the relevant field/enum limitations; no newer contract was found that resolves them.
- [English GetRecord](https://www.alibabacloud.com/help/en/edge-security-acceleration/esa/api-esa-2024-09-10-getrecord), updated **Oct 27, 2026**; [English UpdateRecord](https://www.alibabacloud.com/help/en/edge-security-acceleration/esa/api-esa-2024-09-10-updaterecord), updated **Oct 28, 2026**; [Manage DNS records](https://www.alibabacloud.com/help/en/edge-security-acceleration/esa/user-guide/manage-dns-records-new), updated **Oct 12, 2026**.

## Actual UpdateRecord mapping, not an all-GET JSON echo

The official SDK's entire top-level Update request is:

```text
RecordId (required), Data (required), Type, Ttl, Proxied,
BizName, Comment, SourceType, AuthConf, HostPolicy, HttpPorts, HttpsPorts
```

The entire legal nested `Data` request is:

```text
Value, Priority, Flag, Tag, Weight, Port, Type, KeyTag,
Algorithm, Certificate, Usage, Selector, MatchingType, Fingerprint
```

`AuthConf` legal members are `AccessKey`, `AuthType`, `Region`, `SecretKey`, `Version`. Their description inconsistencies remain outside the proposed CNAME-excluding scope.

| GET field | Legal Update representation / classification |
| --- | --- |
| `RecordId` | Native mutation target, not a replaceable setting. |
| `RecordType` | `Type`; exact combined `A/AAAA` identity must remain native. Terraform treats its configured type as ForceNew and does not send Type on update. |
| `Data.Value` | `Data.Value`; a singleton IPv4 would be replaced as one whole native value, never split into synthetic address records. |
| Other `Data` members listed above | Same named legal setters. They describe other RR formats; do not invent numerical defaults for address records. |
| `Ttl`, `Proxied`, `BizName`, `Comment` | Same named legal setters. Preserve actual applicable observed values rather than guessed defaults. |
| `RecordSourceType` | **`SourceType`**, not an echo under the GET name; documented for CNAME. |
| `AuthConf`, `HostPolicy` | Legal setters, explicitly CNAME-related; outside initial address-only scope. |
| `HttpPorts`, `HttpsPorts` | Legal setters. They are mutable proxy access controls, not immutable metadata. Terraform does not expose these in this resource. |
| `CustomPort` | GET-only `on`/`off` indicator for custom-port enablement; no legal setter here. Docs do not state an exact derivation formula. Do not echo it as an invented Update member. |
| `Data.Tags` | GET-only object described simply as “tags of the record”; no legal nested setter. Distinct from legal singular CAA `Data.Tag`. No proof found that this object is independently mutable routing state, nor that it is purely derived metadata. Do not demand an illegal echo or silently classify it as a routing policy. |
| `SiteId`, `SiteName`, `RecordName` | Identity checked by reads; not mutable Update members. Terraform uses ForceNew for site/name. |
| `CreateTime`, `UpdateTime`, `RecordCname` | Output information, not mutable Update members; timestamps are expected to change normally. |

There is **no record `Status` member in these Get/Update models or resource**, so `Status=enabled` is not a sourced payload. Site `Status=active` is a separate precondition. If shared code needs a record-enabled flag, that requires a documented operational interpretation, not fabrication of a returned API field.

Similarly, **`BizName=dns` is not a documented enum/default**. Terraform documentation explicitly says “Leave the parameter empty if your record is not proxied”; its named values are acceleration businesses `image_video`, `api`, `web`. Update lists `video_image`, `api`, `web`. Empty/omitted business for unproxied records is supported documentation; it does not prove arbitrary server omission preservation or that GET always returns an empty string rather than absence.

## What the Terraform payload actually proves

`resourceAliCloudEsaRecordUpdate` constructs a POST request with `RecordId`, plus `Data` reconstructed from the configured/read Terraform block whenever that block is non-nil. It sends these top-level fields **only when changed**:

```text
Comment, AuthConf, Ttl, HostPolicy, BizName, Proxied, SourceType
```

It never sends `Type`, `HttpPorts`, `HttpsPorts`, `CustomPort`, `Data.Tags`, site/name identity, or timestamps on update. Then it calls `RpcPost("ESA", "2024-09-10", "UpdateRecord", ...)` and rereads via GetRecord.

This is real first-party evidence of **intended partial-update semantics**, appreciably stronger than generic SDK optional/nil serialization. It is **not** a server-preservation specification or an observed passing acceptance run. Nested Data is reconstructed, not patched. Its integer checks compare interface values to the empty **string**, so an integer zero satisfies `value != ""`; ordinary Terraform zero values can consequently be included. Therefore one cannot describe the test's “data-only update” as a captured exact `Data={"Value":...}` request or take generated zero integers as vendor defaults.

The published test source has six cases: **SRV, SMIMEA, CNAME, CERT, SSHFP, CAA**. The CNAME case creates a proxied S3 record with `BizName=api`, host policy, TTL, comment and authentication; changes only business to `web`; then changes only the Data value; later changes TTL, comment, source/authentication and host policy, with a final import verification. This is useful evidence that the first-party author intends omitted top-level settings to survive. There is **no ordinary unproxied `A/AAAA` acceptance case** in this inspected test file, no captured singleton-IPv4 Get/Create/Update response sequence, and no assertions for omitted `Tags`/`CustomPort`/port settings. Test source is not a successful test result. The nearby fixture file supplies certificate/private-key strings for other resources, not ESA Record response fixtures.

## Narrowing that is actually supported, and its limits

1. **Singleton IPv4 in native `A/AAAA` is compatible with the published Data.Value rule.** At least one IPv4 is required; one literal IPv4 satisfies it. No IPv6 identity resolution is needed for an expressly IPv4-only scope. English prose remains inconsistent about separate `A`/`AAAA`, but the combined wire type is present in official Get/Update and Terraform docs. Do not advertise literal native `A` support or AAAA support from this finding.
2. **Unproxied DNS-only mode exists.** The current management guide says advanced HTTP/HTTPS port configuration is available only for A/AAAA or CNAME with **Proxied on**, and is not displayed for unproxied records. Thus ports are operationally inapplicable to an unproxied initial mode; lack of CustomPort echo alone is not a lossless-update blocker. The guide's default extra-port selections concern the console's proxy controls, not an ordinary unproxied API response fixture.
3. **CNAME auth/source/host controls and acceleration-business enum disagreements can be excluded.** They are not reasons to require illegal or irrelevant setters for singleton IPv4. Any non-applicable fields returned must nevertheless be classified explicitly; unknown applicable settings cannot simply be dropped.
4. **The required local capability does not exist yet.** [Shared policy](<../src/providers/common.rs#L62-L88>) has `NameFormat::Fqdn`, which is appropriate for native ESA names. [The registry](<../src/providers/registry.rs>) now distinguishes `supports_dns_read`; its tests establish the review-time **23 implemented / 22 DNS-readable + callback** snapshot. That boolean does not encode supported record families. A future proposal needs explicit `supported_record_types=["A"]` (and a clear singleton-IPv4-combined-native scope), early AAAA rejection, native type retained in extra data, and no fabricated literal-AAAA/native-A claim. None was implemented in this review.

## Concrete remaining evidence gaps

A narrowly approved implementation is **plausible**, not proved impossible. What is missing for the requested source-proven unblock is:

- A first-party ordinary **unproxied singleton-IPv4 native `A/AAAA` Get/Create/Update example or acceptance contract** establishing actual returned applicable/default/absent settings. The omnibus GetRecord example is not such a fixture: it combines `RecordType=A/AAAA` with `Data.Value=example.com`, certificate/SRV/CAA fields, proxied OSS authentication and TTL 20, outside the legal explicit TTL range. It cannot supply invented ordinary defaults.
- A proved legal preservation strategy for that real response: either explicit reconstruction of every applicable mutable setting from GET, or a first-party omission/preservation contract for the omitted settings. The current Terraform source is evidence of client intent, but does not establish that `Data.Tags` is derived/independent or that absent/default ordinary settings remain semantically unchanged on the server. An explicit proof of derived output-only metadata would eliminate the need to preserve it via illegal setters. Merely having no setter is not proof of its derivation.
- No invented `BizName=dns`, `Status=enabled`, port selections, zero-valued Data defaults, empty-object reset semantics, or nil-preserves-server-state inference. `Proxied=false`, native `Type=A/AAAA`, legal TTL and literal Data.Value are individually supported fields; composing them with guessed remaining defaults is not an observed complete accepted ordinary payload.

The already-known complete-hostname inventory requirements remain independently necessary: ordinary ListRecords excludes edge-container, edge-routine and transport-layer records; their site inventories exist and must not be substituted with an empty result after permission/feature errors. Active exact NS site, no version management, fresh complete selection, single writer and strict postread requirements remain prospective, not verified here. These are not newly discovered claims of API impossibility.

## Recommended decision

Keep ESA **unimplemented for now under the requested proof standard**. Preserve the useful narrowed candidate and the complete legal setter mapping above. Reopen the decision if an actual first-party ordinary IPv4 payload/response sequence or explicit semantic preservation/derived-field contract arrives; do not insist on illegal copying of immutable/read-only fields, and do not substitute an always-blocked adapter for contract proof.

Local upstream [aliesa.go](<../../ddns-go/dns/aliesa.go#L180-L211>) only sends type/value/TTL and accepts the update acknowledgement; its [first-record selection](<../../ddns-go/dns/aliesa.go#L215-L240>) is not a source of preservation proof. No upstream unsafe behavior was imported.

Research limits: public source/doc fetches only; public web search was unavailable because its backend lacked a search credential, and GitHub REST was rate-limited, so source paths were discovered through the public GitHub tree instead. No live ESA API, credentials or acceptance tests were used. No compilation/test claim is made for an unimplemented adapter.
