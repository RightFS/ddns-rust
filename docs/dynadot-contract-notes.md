# Dynadot contract investigation — deferred, not implemented

Inspected **2026-11-09**. This is research evidence, not a supported-provider announcement. No Dynadot adapter, example, registry entry, credentials, cloud reads/writes, or completed mock validation are supplied by this investigation. A temporary unintegrated adapter draft was removed when the rollout decision changed to defer.

## Official public sources

**Follow-up qualification:** the [focused v2 second opinion](<dynadot-v2-second-opinion.md>) freshly parsed the entire official command dataset. Specific DELETE JSON is a defensible exception to generic no-body guidance; finite flag/mode differences and irrelevant v1 casing alone do not universally block v2. Destructive matching/defaults, same-host additive coexistence, sub-only payload acceptance, complete active DNS state and untouched TTL/mail/settings remain unproved. New required-main-list/same-subhost error text is an acceptance question, not proof that add-before-remove is impossible.

The primary `www.dynadot.com` documentation pages returned Cloudflare verification/HTTP 403 during this investigation. Dynadot's public regional site exposed the current documentation and the same documentation frontend's machine-readable data. These are documentation requests, not authenticated DNS API calls.

- [Current REST documentation](https://dynadot.com.cn/domain/api-document) — version selector includes V1.0.0 and V2.0.0 Beta; general authentication/signing and response conventions.
- [Legacy API documentation](https://www.ddot.in/domain/api-commands) — explicitly says “Legacy API, Scheduled for Retirement. Please use our RESTful API instead”.
- [Official frontend machine documentation, v1](https://dynadot.com.cn/dynadot-vue-api/dynadot-service/api-document-data-api?command=get_api_command_info_data&apiVersion=1.0.0&lang=en).
- [Official frontend machine documentation, v2](https://dynadot.com.cn/dynadot-vue-api/dynadot-service/api-document-data-api?command=get_api_command_info_data&apiVersion=2.0.0&lang=en).

The public frontend fetches this data using `command=get_api_command_info_data`, `apiVersion`, and `lang`. The machine documentation is **not** evidence that the live DNS-mode wire response has been exercised or confirmed.

## Why not blindly port upstream or legacy whole-zone replacement?

The local upstream adapter [dynadot.go](../../ddns-go/dns/dynadot.go) uses `GET https://www.dynadot.com/set_ddns` with the dynamic password in `pwd` and parameters `domain`, `subDomain`, `type`, `ip`, `ttl`, and `containRoot`. It has no authenticated authoritative DNS inventory or zone-status read. Therefore it cannot establish the required disabled/ambiguity/ID/CNAME/delegation checks or fresh absence/prewrite proof. It is not a safe replacement for a read/reconcile adapter.

REST v1 documents GET/POST `/restful/v1/domains/{domain_name}/records`. POST is `set_dns`, with `add_dns_to_current_setting=false` by default. There is no `remove_dns` command in the retrieved v1 command inventory. Its additive option alone does not provide an existing-IP replacement operation. Full replacement must not silently omit unrelated records or settings.

The read model includes nameserver, advertising, domain forwarding, stealth title, email forwarding/aliases/MX settings, and DNS lists; `set_dns` does not provide a general lossless setter for those settings. A future full-zone implementation would need proven complete-state preservation and must reject unsupported settings before **all** noop/dry-run/write paths. This investigation does not assert that such preservation is impossible; it has not verified a sufficient round-trip contract.

## V2 is a real potential capability, but explicitly Beta

The official documentation says:

> Beta Notice: This API documentation is Beta. Endpoints, fields, error codes, and behaviors may change without notice and backward compatibility is not guaranteed. Avoid relying on it for critical production workflows.

V2 provides documented exact-value removal, unlike the retrieved v1 inventory. A future isolated, **explicit noncritical-beta opt-in** adapter could use additive creation followed by exact old-value removal. It must never silently fall back to full replacement.

Compact excerpts from the official v2 machine documentation:

```json
{
  "commandName": "get_dns",
  "apiVersion": "v2",
  "requireSignature": true,
  "requestDemoJson": {
    "requestHeader": {
      "Method": "GET",
      "URL": "https://api.dynadot.com/restful/v2/domains/{domain_name}/records",
      "Authorization": "Bearer ",
      "Signature": "{signature}"
    },
    "requestBody": {}
  }
}
```

Its `ResponseParameters` describes `data.glue_info` with `glue_type`, `ttl` (String), `dns_main_list`, and `dns_sub_list`. The ordinary record fields are `record_type`, `record_value1`, `record_value2`; subrecords additionally have `sub_host`. No native per-record IDs or record-level enabled state are documented here. DNS arrays are described as optional; absence must **not** be interpreted as a proven empty full-zone inventory without clarification.

```json
{
  "commandName": "set_dns",
  "apiVersion": "v2",
  "requireSignature": true,
  "requestDemoJson": {
    "requestHeader": {
      "Method": "POST",
      "URL": "https://api.dynadot.com/restful/v2/domains/{domain_name}/records"
    },
    "requestBody": {
      "dns_main_list": [{
        "record_type": "String",
        "record_value1": "String",
        "record_value2": "String"
      }],
      "dns_sub_list": [{
        "sub_host": "String",
        "record_type": "String",
        "record_value1": "String",
        "record_value2": "String"
      }],
      "ttl": 0,
      "add_dns_to_current_setting": false
    }
  }
}
```

`0`, `"String"`, and `false` above are **documentation demo placeholders/defaults, not safe production payload values**. The request parameter descriptions specify main-list maximum 20, sub-list maximum 100, TTL default 86400, and additive flag default false. An additive adapter must set `add_dns_to_current_setting=true` explicitly on every POST and send only the intended added tuple. It needs spare capacity for add-before-remove.

```json
{
  "commandName": "remove_dns",
  "apiVersion": "v2",
  "requireSignature": false,
  "requestDemoJson": {
    "requestHeader": {
      "Method": "DELETE",
      "URL": "https://api.dynadot.com/restful/v2/domains/{domain_name}/records"
    },
    "requestBody": {
      "dns_main_list": [{
        "record_type": "String",
        "record_value1": "String",
        "record_value2": "String"
      }],
      "dns_sub_list": [{
        "sub_host": "String",
        "record_type": "String",
        "record_value1": "String",
        "record_value2": "String"
      }]
    }
  }
}
```

The removal HTTP-200 demo is:

```json
{
  "code": 200,
  "message": "Success",
  "data": {
    "main_record_removed_count": 1,
    "sub_record_removed_count": 1
  }
}
```

That demo removes one of each kind. A single-record adapter must instead require **one intended-kind removal and zero other-kind removals**, then prove exact full-state readback. A bare 2xx, vague success, or missing removal count must not be treated as confirmed replacement. No automatic retries, rollback, or whole-RRset deletion are acceptable.

## Material schema/sample conflicts and unanswered contracts

1. **V1 domain-info shape and casing differ.** `ResponseParameters` specifies `data.domain_info` Object, `domain_name`, `glue_info`, and Boolean flags. Its official JSON demo instead uses `data.domainInfo` Array, `domainName`, `glueInfo`, `udrpLocked`, and `"Yes"` strings. A production adapter must not fabricate a single verified wire shape from this contradiction.
2. **V1 glue-mode shape differs.** GET records parameters describe `name_server_settings.glue_type`, with `type_dns`/`type_park` enum-style values. Its demo uses `name_server_settings.type = "Dynadot Parking"`. The retrieved example is parking mode, not complete DNS mode.
3. **V1 read/write sub-list names differ.** Read parameter descriptions use `dns_sub_list`; POST `set_dns` uses `sub_list`. This is a real version-specific mapping to verify, not a reason to copy GET JSON into POST blindly.
4. **V2 status flag types still differ.** Its domain-info parameters say `disabled`, `udrp_locked`, `registrant_unverified`, `hold`, and `locked` are Boolean. The official JSON sample supplies `"Yes"` strings. Missing/unknown flag values cannot be assumed false. Supporting the documented Boolean and Yes/No forms may be possible, but requires deliberate fixtures and fail-closed tests.
5. **V2 mode casing differs.** Supported values describe `dns`, `registrar_parking`, etc.; the demo uses `"REGISTRAR_PARKING"`. No retrieved DNS-mode sample demonstrates the actual complete arrays, TTL, or inactive-setting field encodings.
6. **DELETE body guidance conflicts.** The general overview says DELETE “does not have a request body”; the command-specific v2 `remove_dns` demo explicitly has JSON record lists. Command-specific documentation is promising, but exact accepted payload/body behavior needs clarification or reliable non-live fixtures before the adapter is claimed validated.
7. **Signing header guidance differs.** General REST documentation names `X-Signature`; machine-command request demos show `Signature`. The general documented signing procedure is concrete; the header inconsistency must not be hidden.
8. **Unused second-value absence is unspecified.** `record_value2` is optional and unused for A/AAAA. The contract must establish whether missing, empty string, or null values are equivalent for exact matching and removal. Guessing an empty value may not prove preservation of observed metadata.
9. **Full inventory completeness is unconfirmed.** GET records has no documented pagination parameters, while DNS arrays are optional. The adapter needs complete arrays within documented limits, must reject pagination/truncation/unknown fields, and must not equate missing lists with absence.

Compact sample illustrating v2 domain-info flag inconsistency:

```json
{
  "code": 200,
  "message": "Success",
  "data": {
    "domain_info": {
      "domain_name": "example.com",
      "glue_info": {
        "glue_type": "REGISTRAR_PARKING",
        "with_ads": "Yes"
      },
      "disabled": "Yes",
      "udrp_locked": "Yes",
      "registrant_unverified": "Yes",
      "hold": "Yes",
      "status": "status"
    }
  }
}
```

This is an abbreviated official parking-mode demo, **not** an active DNS-mode fixture. `"status"` is a placeholder; it is not proof of the required `active` state.

## Authentication, TTL, identity and safeguards for a future implementation

- REST uses Bearer API key. General docs require API secret HMAC-SHA256 signing for sensitive operations. The signing input is `apiKey + "\n" + fullPathAndQuery + "\n" + xRequestIdOrEmpty + "\n" + exactRequestBodyOrEmpty`; result is standard Base64 using the API secret as HMAC key. The optional request ID must be UUID-shaped. A suitable constructor is `Dynadot::new(client, api_key, api_secret, &options)`, using existing secret-environment handling rather than storing the secret in options.
- Proposed required option: `api_mode = "v2_beta"`, explicitly acknowledging noncritical Beta use. Disabled example, `create_if_missing=false`, fixed production REST hostname, test-only localhost override, no V1 fallback.
- Every call's diagnostic redaction must cover the key, secret, generated signature, and encoded forms. Sensitive header values, redirects disabled, no raw URL/body/header/signature logging, strict deadlines, bounded responses, no write retries.
- TTL is a **zone setting**. Require configured record TTL to equal observed existing zone TTL **before noop, dry-run, create, or update**. Preserve that same TTL on additions if omission could reset it to 86400. Never change global TTL to satisfy an individual configured record. This is not a provider-managed-unreadable-TTL workaround: the schema describes actual TTL reads/writes.
- No native record IDs are described. Use stable logical domain/host/type singleton IDs, not positional indexes. Multi-value RRsets must be rejected even when selecting a diagnostic member ID. Duplicate identical tuples make exact-value removal unsafe.
- Independently authenticate and verify exact domain identity, active/enabled/verified/not-held/non-UDRP state, and Dynadot DNS mode. Reject CNAME conflicts, delegated child NS, unknown state/settings, malformed values, missing identity, disabled and ambiguous targets before noop/dry-run.
- Fresh creation-absence proof, whole-state prewrite comparison, add-only payload, full addition readback, another fresh proof before exact old-value removal, exact removal counts, and final full readback are required. Preserve TXT/MX/CAA/SRV/other unrelated ordinary records and all settings. Unknown/managed settings must fail closed. Races after the final read remain possible without CAS; partial updates may leave both IPs and require manual recovery.

## Exact prerequisites before resuming implementation

1. Obtain **redacted non-live DNS-mode fixtures** (archived responses, provider-issued examples, or controlled sandbox evidence supplied by the user), or official clarification, for v2 GET domain-info and GET records: active domain flags, complete apex/subrecord arrays, real TTL representation, empty arrays, inactive settings, multiple records, and unused second-value representation. Do not request credentials or make live cloud calls to discover these shapes.
2. Clarify `X-Signature` versus `Signature`, command-specific DELETE JSON body semantics, exact tuple matching/default behavior, synchronous addition acknowledgement, removal-count shape, and additive TTL preservation.
3. Confirm that explicit Beta acceptance is appropriate for the intended **noncritical** workload; do not market the resulting implementation as stable production support.
4. Only then implement the isolated adapter/example and comprehensive localhost Axum tests with independent signing golden vectors, stale/partial-state faults, exact payload/count/readback checks, status/identity/ambiguity/conflict rejection, capacity/completeness checks, timeout/redirect/auth/redaction tests, and no-op/dry-run zero-write assertions.

Until these prerequisites are met, **implemented = false**. Public documentation retrieval is complete research; it is not completed mock validation or operational provider support.
