# Windows Authentication and Privilege CIM Records v1

Status: **NORMATIVE SPECIFICATION**  
Contract family: `1.x`  
JSON Schema: 2020-12  
ECS baseline: `9.5.0`

## 1. Scope

This specification establishes the canonical HostHunter records for Windows
process creation and termination, authentication activity, primary
process-token privileges, and a person's policy-effective user rights on a
target host. It defines the
normalized JSON that HostHunter must eventually produce and the HostHunter
Visualizer must eventually accept, preserve, correlate, and display.

Registration of a record establishes validation and immutable generic storage;
it does not by itself enable a collector, run post-processing, or add a
visualizer view. Those implementation steps must conform to this contract.

## 2. Canonical Record Catalogue

| Canonical name | Version | Source | Meaning |
| --- | --- | --- | --- |
| `process.start` | `1.0.0` | Security 4688 v0/v1/v2 | A process was created |
| `process.end` | `1.0.0` | Security 4689 v0 | A process ended |
| `authentication.session.start` | `1.0.0` | Security 4624 v0/v1/v2 | A successful logon created a session |
| `authentication.logon.failure` | `1.0.0` | Security 4625 v0 | A logon attempt failed |
| `authentication.session.end` | `1.0.0` | Security 4634 v0 | A logon session ended |
| `authentication.session.logoff-initiated` | `1.0.0` | Security 4647 v0 | A user initiated logoff |
| `authentication.explicit-credential-use` | `1.0.0` | Security 4648 v0 | A process attempted to use explicit credentials |
| `authentication.session.special-privileges` | `1.0.0` | Security 4672 v0 | Sensitive privileges were assigned to a new logon |
| `process.access-token` | `1.0.0` | Windows primary process token | Point-in-time privilege state on the primary token |
| `user.effective-rights` | `1.0.0` | Target-host effective policy plus resolved group membership | A person's effective user-right assignments and their origins |

All records use `schemas/forensic-event-envelope.v1.schema.json`. Immutable
source activities use `event.kind: event`; point-in-time observations use
`event.kind: state`.

## 3. Producer Boundary

HostHunter must decode and normalize evidence before delivery. A conforming
record contains only declared canonical JSON fields. It must not contain raw
EVTX, XML, native event-data bags, localized message tokens such as `%%1936`,
encoded hexadecimal process identifiers, dedicated credential secrets,
passwords, or opaque undecoded values. A collected process command line is a
declared sensitive evidence field and is preserved in full even when its text
incidentally includes credential-like material; it is never decoded into a
dedicated password, token, key, ticket, or credential field.

The following transformations are mandatory:

- hexadecimal PIDs become JSON unsigned integers;
- hexadecimal logon IDs and other LUIDs become unsigned decimal strings;
- NTSTATUS and substatus become unsigned 32-bit integers, with an optional
  stable symbolic name;
- `-`, empty values, and all-zero GUID placeholders are omitted;
- source ports become integers;
- Windows privilege names remain stable `Se...Privilege` identifiers;
- native boolean/message tokens become JSON booleans;
- logon type becomes an integer plus a canonical lower-case name;
- timestamps become RFC 3339 UTC;
- arrays are de-duplicated without losing distinct provenance.

HostHunter preserves provider, channel, event code and version, record ID,
source computer, collection time, transport, and exact normalizer identity.
The visualizer must validate every record against its named schema before
durable acceptance.

## 4. Identity and Correlation

- `event.id` identifies one immutable canonical source event or observation
  using the deterministic UUIDv5 algorithm in the producer contract.
- `host.id` is the stable endpoint identity. Hostname and IP are not identity.
- `host.boot.id` is the source-defined boot identity. HostHunter should populate
  it whenever the source activity or observation can be assigned to a boot.
- A Windows logon ID is scoped to its source host and boot. It is not globally
  unique and must never be correlated without the host and relevant time.
- `process.entity_id` is the HostHunter-backed process identity defined by the
  producer contract. It is based on a canonical process-start event or a
  verified PID/start-time pair and is reused on every record for that instance.
- A PID is scoped to a host, boot, and time. It is not a stable process identity.
- `4634` is the event that proves a logon session ended. `4647` records intent
  to log off and must never close a session by itself.
- `4648` proves an explicit-credential attempt, not successful authentication.
- `4672` is retained as its own event and may enrich a matching `4624`; it is
  not a complete enumeration of the resulting access token.
- Derived links never modify the accepted immutable records and must expose
  whether correlation is exact, derived, ambiguous, or unresolved.

Both correlation identifiers are optional additions to the already enabled
`1.0.0` records. Their absence preserves schema compatibility but prevents the
visualizer from claiming identifier-exact correlation. A future major schema
version may make either field mandatory after producer support is proven.

## 5. Security Event 4688 - Process Start

Normative schema: `schemas/process-start.v1.schema.json`.

The existing `process.start/1.0.0` record remains authoritative. The standalone
`Get-ProcessStartEvents` module is a collection reference only and must be
changed during its own implementation work to emit this record exactly.

| Native concept | Canonical field |
| --- | --- |
| Event time | `@timestamp` |
| Host boot identity | `host.boot.id` |
| New Process ID | `process.pid` |
| Stable process instance | `process.entity_id` |
| New Process Name | `process.executable`, derived basename in `process.name` |
| Process Command Line | `process.command_line` |
| Token Elevation Type | `process.token_elevation` |
| Mandatory Label | `process.integrity_level` |
| Creator Process ID | `process.parent.pid` |
| Creator Process Name | `process.parent.executable`, derived basename in `.name` |
| Creator Subject | `user.*` |
| Target Subject | `hosthunter.process.target_user.*` |
| Event version and record | `hosthunter.source.*` |

Version 0 excludes command line, integrity, creator-process name, and target
subject. Version 1 may include command line but excludes the v2-only fields.
Version 2 may contain every declared field.

## 5.1 Security Event 4689 - Process End

Normative schema: `schemas/process-end.v1.schema.json`.

`process.end/1.0.0` preserves Security 4689 version 0 as a separate immutable
record. It never edits or closes a `process.start` document.

| Native concept | Canonical field |
| --- | --- |
| Event time | `@timestamp`, `process.end` |
| Host boot identity | `host.boot.id` when verified |
| Process ID | `process.pid` |
| Stable process instance | `process.entity_id` only when verified against a start |
| Process Name | `process.executable`, derived basename in `process.name` |
| Exit Status | `process.exit_code` as an unsigned 32-bit integer |
| Terminating Subject | `user.*` |
| Event version and record | `hosthunter.source.*` |

Event 4689 contains no process start time, parent, command line, or duration.
Those fields are not copied from another event. Exit-status meanings are
application-specific, so the record does not infer `event.outcome`. A PID-only
termination remains unmatched unless derived processing finds one defensible
earlier process instance; ambiguous or absent candidates remain explicit.

## 6. Security Event 4624 - Successful Logon

Normative schema: `schemas/authentication-session-start.v1.schema.json`.

| Native field/concept | Canonical field | Rule |
| --- | --- | --- |
| TimeCreated | `@timestamp` | Source event time |
| SubjectUserSid/Name/DomainName/LogonId | `user.*` | Actor requesting the logon |
| TargetUserSid/Name/DomainName/LogonId | `user.target.*` | Newly logged-on principal/session |
| LogonType | `hosthunter.authentication.logon_type` | Decoded ID and canonical name |
| LogonProcessName | `hosthunter.authentication.logon_process` | Omit native placeholders |
| AuthenticationPackageName | `hosthunter.authentication.authentication_package` | Normalized text |
| LogonGuid | `hosthunter.authentication.logon_guid` | Omit zero GUID |
| TransmittedServices | `hosthunter.authentication.transmitted_services` | Decoded unique services |
| LmPackageName | `hosthunter.authentication.ntlm_package` | Present only when reported |
| KeyLength | `hosthunter.authentication.key_length_bits` | Integer bits |
| ProcessId/ProcessName | `process.pid/executable/name` | Decoded caller process |
| WorkstationName | `source.address` | Source label, not endpoint identity |
| IpAddress/IpPort | `source.ip/port` | Normalized address and integer port |
| ImpersonationLevel | `hosthunter.authentication.impersonation_level` | v1 and v2 only |
| RestrictedAdminMode | `hosthunter.authentication.restricted_admin_mode` | v2 only |
| VirtualAccount | `hosthunter.authentication.virtual_account` | v2 only |
| ElevatedToken | `hosthunter.authentication.elevated_token` | v2 only |
| TargetLinkedLogonId | `hosthunter.authentication.linked_logon_id` | v2 decimal LUID |
| TargetOutboundUserName/DomainName | `hosthunter.authentication.outbound_user.*` | v2 only |
| TargetLogonGuid | `hosthunter.authentication.target_logon_guid` | v2; omit zero GUID |

`event.outcome` is `success`. This means the session was created, not that a
later activity performed by the principal succeeded.

`user.target.logon_id` is mandatory in every canonical 4624 record. A producer
that cannot decode `TargetLogonId` must reject or quarantine the source event;
it must not emit a session-start record that cannot identify its new session.

## 7. Security Event 4625 - Failed Logon

Normative schema: `schemas/authentication-logon-failure.v1.schema.json`.

| Native field/concept | Canonical field | Rule |
| --- | --- | --- |
| SubjectUserSid/Name/DomainName/LogonId | `user.*` | Reporting/initiating security context |
| TargetUserSid/Name/DomainName | `user.target.*` | Account used in the failed attempt |
| Status | `hosthunter.failure.status_code/status_name` | uint32 plus optional stable symbol |
| SubStatus | `hosthunter.failure.sub_status_code/sub_status_name` | uint32 plus optional stable symbol |
| FailureReason | `hosthunter.failure.reason` | Decoded bounded explanation |
| LogonType | `hosthunter.authentication.logon_type` | Decoded ID and name |
| LogonProcessName | `hosthunter.authentication.logon_process` | Normalized text |
| AuthenticationPackageName | `hosthunter.authentication.authentication_package` | Normalized text |
| TransmittedServices/LmPackageName/KeyLength | Corresponding `hosthunter.authentication.*` fields | Omit absent values |
| CallerProcessId/CallerProcessName | `process.pid/executable/name` | Decoded caller process |
| WorkstationName/IpAddress/IpPort | `source.address/ip/port` | Normalized source |

`event.outcome` is `failure`. The status code remains evidence; the visualizer
must not substitute a generic reason for a more precise collected value.

## 8. Security Event 4634 - Session End

Normative schema: `schemas/authentication-session-end.v1.schema.json`.

| Native field | Canonical field |
| --- | --- |
| TargetUserSid/Name/DomainName/LogonId | `user.*` |
| LogonType | `hosthunter.authentication.logon_type` |
| Source provenance | `hosthunter.source.*` |

The event ends the session identified by host plus decimal `user.logon_id`.
`event.outcome` is `success` because the source records session termination.

## 9. Security Event 4647 - User-Initiated Logoff

Normative schema:
`schemas/authentication-session-logoff-initiated.v1.schema.json`.

Subject SID, name, domain, and decimal logon ID map to `user.*`. The record has
`event.type: ["info"]` and deliberately has no outcome. It records user intent;
it neither proves success nor ends the correlated session without `4634`.

## 10. Security Event 4648 - Explicit Credentials Used

Normative schema:
`schemas/authentication-explicit-credential-use.v1.schema.json`.

| Native field/concept | Canonical field | Rule |
| --- | --- | --- |
| SubjectUserSid/Name/DomainName/LogonId | `user.*` | Actor/process security context |
| TargetUserName/TargetDomainName/TargetUserSid | `user.target.*` | Principal whose credentials were supplied |
| ProcessId/ProcessName | `process.pid/executable/name` | Required caller process |
| TargetServerName | `destination.address` | Target label |
| TargetInfo | `hosthunter.authentication.target_info` | Bounded target context, never a secret |
| IpAddress/IpPort | `source.ip/port` | Normalized source when present |
| TargetLogonGuid | `hosthunter.authentication.target_logon_guid` | Omit zero GUID |

`event.outcome` is `unknown`: the source proves attempted explicit credential
use, not that the credentials were accepted. Passwords, hashes, tickets,
tokens, and other credential material are prohibited.

## 11. Security Event 4672 - Special Privileges Assigned

Normative schema:
`schemas/authentication-session-special-privileges.v1.schema.json`.

Subject SID, name, domain, and decimal logon ID map to `user.*`. PrivilegeList
is decoded to the unique `hosthunter.privileges` array of stable
`Se...Privilege` names. The record is preserved even when correlated with a
4624 session. It does not say which privileges are enabled, removed, or later
used and must not be displayed as a complete process-token snapshot.

## 12. Primary Process Access Token

Normative schema: `schemas/process-access-token.v1.schema.json`.

This point-in-time record describes only the primary token of the identified
process. Thread impersonation tokens are outside v1. A `complete` observation
must identify the process with more than a bare reusable PID by including
`process.entity_id` or a verified `process.start` timestamp. A bare-PID result
is at most `partial`, even when token enumeration otherwise succeeded.

Each privilege records:

| Field | Meaning |
| --- | --- |
| `name` | Stable Windows `Se...Privilege` name |
| `enabled` | Enabled in the observed token |
| `enabled_by_default` | Enabled by default on token creation |
| `removed` | Marked removed in the observed token attributes |
| `used_for_access` | Marked used for an access check |

Privilege names must occur once per record. `complete` means stable process
instance evidence, token owner, the primary-token marker, token identity where
available, and the complete enumerated privilege list are present. `partial`
preserves all known values and issues. `unavailable` or `failed` contains no
invented empty privilege list and uses an explicit issue.

This record is runtime truth for the observed process. A user-right assignment
must never be used to infer that a privilege exists or is enabled in a token.

## 13. Effective User Rights and Their Origins

Normative schema: `schemas/user-effective-rights.v1.schema.json`.

The record answers: **which rights does this person effectively hold under the
target host's effective security policy, and through which assignments and
group memberships did each right arise?** It is target-host policy truth, not
a claim about a process token or a successful logon.

### 13.1 Required resolution

HostHunter must:

1. resolve the target user by SID;
2. resolve the user's direct and transitive enabled group memberships relevant
    to the target host;
3. enumerate direct right assignments for the user and every resolved group;
4. calculate deny-overrides-allow behavior for paired logon rights;
5. retain every contributing assignment and membership path;
6. attribute the exact Local Policy, GPO, or MDM source only when independently
    observed; otherwise record an explicit unknown policy source.

An origin with `relationship: direct` names the user in `assigned_to` and has
no membership path. An origin with `relationship: group_membership` contains a
complete ordered `membership_path` whose first principal is the target user,
whose last principal equals `assigned_to`, and whose intermediate principals
show every nested group hop. Example:

```text
LAB\alice -> LAB\IT Support -> BUILTIN\Administrators
```

Every separately contributing path is retained. A single convenient group is
not substituted for the complete path.

### 13.2 Policy-source attribution

`policy_source.attribution_status: observed` is allowed only when separately
collected evidence identifies the source, such as local LSA policy, Resultant
Set of Policy/group-policy results, or Policy CSP/MDM evidence. The record then
identifies its type and supporting evidence and may include its stable ID/name.

The LSA effective assignment alone proves which principal is assigned a right;
it does not prove which GPO or management system caused that assignment. When
that causal source is not proven, the origin must be:

```json
{
  "attribution_status": "unknown",
  "type": "unknown",
  "evidence": "unknown"
}
```

Unknown is not an error and must never be replaced with a guess.

### 13.3 Right kinds and precedence

- Privileges use `kind: privilege`, `effect: grant`, and `state: effective`.
- Positive logon rights use `kind: logon_right` and `effect: allow`.
- Deny logon rights use `kind: logon_right`, `effect: deny`, and remain
  independently visible.
- If an applicable deny right matches an allow right, the allow assignment is
  retained with `state: overridden` and names the deny right in
  `overridden_by`; the deny remains `state: effective`.

The v1 paired rights are:

| Allow | Deny |
| --- | --- |
| `SeNetworkLogonRight` | `SeDenyNetworkLogonRight` |
| `SeBatchLogonRight` | `SeDenyBatchLogonRight` |
| `SeServiceLogonRight` | `SeDenyServiceLogonRight` |
| `SeInteractiveLogonRight` | `SeDenyInteractiveLogonRight` |
| `SeRemoteInteractiveLogonRight` | `SeDenyRemoteInteractiveLogonRight` |

### 13.4 Completeness

- `complete` requires complete membership and assignment resolution. `rights`
  may be an empty array only when HostHunter proved that the resolved person
  has no applicable assignments.
- `partial` retains every proven right and origin, reports issues, and uses
  `event.outcome: unknown`.
- `unavailable` and `failed` omit `rights`, report issues, and use
  `event.outcome: failure`.
- When identity resolution fails, `user` retains the bounded operator-supplied
  name/domain when known and may omit `user.id`; the record must use
  `observation.status: failed`, failed membership/assignment resolution, an
  explicit issue, and no `rights`. Complete and partial observations require
  the resolved SID in `user.id`.
- Failure to resolve nested membership, SID identity, assignments, or deny
  precedence must never be represented as a complete empty result.
- Exact policy-source attribution may be unavailable while membership and
  assignment resolution are complete; each origin then uses explicit unknown
  policy attribution.

## 14. Immutability, Post-Processing, and Display

Each source event or state observation is one immutable record. Post-processing
may link 4624/4634/4647/4672 by host, boot-aware time, and logon ID; link 4648
to its caller process; link 4688 to process-token observations; and project
effective-right origins. It must not collapse distinct source records, invent
missing evidence, suppress a collected record, or overwrite original fields.

If HostHunter collected and validly normalized a record, the visualizer must
retain it and make it available for display. UI grouping and enrichment may be
derived, but the complete canonical evidence remains inspectable.

## 15. Security and Privacy

User names, SIDs, hostnames, IP addresses, command lines, process paths, group
membership paths, and policy names are sensitive investigative data. Access,
retention, logs, fixtures, and exports must be bounded accordingly. Full
collected command lines are intentionally retained as high-value evidence and
may incidentally contain credentials or tokens. They remain inert JSON strings
and must not be copied into ordinary diagnostics, environment variables,
process arguments, or summary receipts. Dedicated credential fields, raw
authentication material, passwords, hashes, tickets, keys, and tokens remain
prohibited.

## 16. Conformance Requirements

Before either repository claims implementation:

- every registered record must validate against its exact schema;
- the schemas and normative examples must be byte-identical in both repos;
- native version fixtures must prove the required field mappings and omissions;
- invalid native/encoded values, secrets, undeclared fields, and unsupported
  versions must be rejected;
- UUIDv5 identity, exact process-identity construction, logon-type pairing,
  unique privilege names, rights-path endpoints, deny precedence, and policy
  attribution must pass the producer contract's semantic validation rules;
- complete, partial, unavailable, failure, replay, and conflict behavior must
  have containerized contract tests;
- API registration, durable storage, post-processing, and display must be added
  in their own implementation work without widening this contract.

## 17. Authoritative Windows References

- [Security Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [Security Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [Security Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [Security Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [Security Event 4648](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648)
- [Security Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [Windows access tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [TOKEN_PRIVILEGES](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges)
- [LsaEnumerateAccountRights](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumerateaccountrights)
- [LsaEnumerateAccountsWithUserRight](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumerateaccountswithuserright)
- [gpresult and resultant policy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult)
