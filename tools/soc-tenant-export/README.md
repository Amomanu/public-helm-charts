# SOC tenant settings export

`Export-SocTenantSettings.ps1` produces a timestamped, self-describing snapshot of the security configuration of a Microsoft Entra ID / Microsoft 365 / Azure tenant.

It exists to answer three questions that come up constantly in SOC work:

- **What is this tenant's security configuration right now?** — onboarding a new customer, or picking up a ticket in an unfamiliar tenant.
- **What changed since last time?** — diff two exports to catch configuration drift or an attacker's persistence change.
- **Where are the blind spots?** — audit logging that is off, alert policies that are disabled, suppression rules and filtering bypasses that hide activity.

It complements per-identity investigation work: an IAM investigation asks what one account did, while this captures the tenant configuration that behaviour has to be judged against.

**The script is strictly read-only.** It issues `GET` requests and `Get-*` cmdlets only, and never modifies tenant state.

---

## Quick start

```powershell
# See every artifact and the permission it needs — no credentials required
./Export-SocTenantSettings.ps1 -ListArtifacts | Format-Table Section, Name, Permission -AutoSize

# Interactive run against one tenant
./Export-SocTenantSettings.ps1 -TenantId contoso.onmicrosoft.com

# Unattended app-only run, everything, zipped for a ticket attachment
./Export-SocTenantSettings.ps1 -TenantId contoso.onmicrosoft.com `
    -AuthMode Certificate `
    -ClientId 00000000-1111-2222-3333-444444444444 `
    -CertificateThumbprint A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 `
    -Depth Extended -Archive

# Identity configuration only, pseudonymised so it can leave the customer boundary
./Export-SocTenantSettings.ps1 -TenantId contoso.com -Include Entra,Applications -RedactUserData
```

## Requirements

| | |
|---|---|
| PowerShell | 7.0 or later (Windows, Linux or macOS) |
| Modules — Graph, ARM, Defender sections | **None.** Tokens are acquired directly from the identity platform and the APIs are called over REST. |
| Modules — Exchange, Defender for Office 365, Purview sections | `ExchangeOnlineManagement` (`Install-Module ExchangeOnlineManagement -Scope CurrentUser`) |
| Modules — `-AuthMode ExistingSession` only | `Az.Accounts`, with an active `Connect-AzAccount` |

If `ExchangeOnlineManagement` is missing, those three sections are reported as `SkippedNoTransport` and the rest of the export proceeds normally.

## Authentication

| `-AuthMode` | Use it for | Notes |
|---|---|---|
| `Certificate` | Unattended and scheduled runs | Recommended. The **only** app-only mode Exchange Online supports. |
| `ClientSecret` | Unattended Graph/ARM/Defender runs | Exchange, Defender for Office 365 and Purview cannot use it — those sections are skipped with an explicit reason. |
| `DeviceCode` | One-off interactive runs | Signs in through a browser. Uses the Microsoft Graph PowerShell first-party client unless you pass `-ClientId`. |
| `ExistingSession` | Azure-focused runs | Borrows a token from an existing `Connect-AzAccount` session. |

### App registration for unattended runs

**Scripted:** [`setup/New-SocAppRegistration.ps1`](setup/New-SocAppRegistration.ps1) does the whole thing — app registration, all 25 Graph permissions, `Exchange.ManageAsApp`, the Defender for Endpoint scopes, admin consent, a certificate, the directory role, and Azure RBAC. It drives the `az` CLI, and resolves every permission ID from the resource service principal at run time rather than hardcoding GUIDs.

```powershell
# everything, including Azure and Sentinel
./setup/New-SocAppRegistration.ps1 -SubscriptionId 00000000-1111-2222-3333-444444444444

# identity configuration only — no Exchange, Purview, Azure or Defender API scopes
./setup/New-SocAppRegistration.ps1 -Sections Entra

# see what it would create and grant, without changing anything
./setup/New-SocAppRegistration.ps1 -WhatIf
```

On Windows it creates the certificate with a CSP key provider, so the Exchange CNG restriction below is handled for you. It prints the client ID, thumbprint and a ready-to-run export command, and lists what it cannot do on your behalf (Sentinel workspace roles, tenant-root Reader).

A bash equivalent, [`setup/new-soc-app-registration.sh`](setup/new-soc-app-registration.sh), is kept for Azure Cloud Shell and Linux hosts where `az` is available but PowerShell is not. Both request an identical permission set.

**By hand:**

1. Create an app registration in the customer tenant.
2. Add the **application** permissions from the matrix below and grant admin consent.
3. Upload a certificate (`Certificates & secrets` → `Certificates`).
4. For the Azure and Sentinel sections, assign **Reader** and **Security Reader** on each subscription, plus **Microsoft Sentinel Reader** on the Sentinel workspaces, and **Reader** at the tenant root for the Entra diagnostic settings artifact.
5. For the Exchange, Defender for Office 365 and Purview sections, see the extra setup under [Exchange and Purview](#exchange-and-purview-extra-setup) — a Graph permission alone is not enough for those.

Run `-ListArtifacts` to produce the exact list for the sections you intend to collect:

```powershell
./Export-SocTenantSettings.ps1 -ListArtifacts -Include Entra,Applications |
    Select-Object -ExpandProperty Permission -Unique | Sort-Object
```

### Permission matrix

Microsoft Graph **application** permissions, all read-only. The section column lets you drop any permission whose section you are not collecting.

| Permission | Artifacts | Needed for |
|---|---|---|
| `Policy.Read.All` | 15 | Entra, Intune |
| `RoleManagement.Read.Directory` | 6 | Entra |
| `Application.Read.All` | 5 | Applications |
| `Directory.Read.All` | 3 | Entra, Applications |
| `Organization.Read.All` | 3 | Entra |
| `Policy.Read.AuthenticationMethod` | 3 | Entra |
| `AuditLog.Read.All` | 2 | Entra |
| `Domain.Read.All` | 2 | Entra |
| `AdministrativeUnit.Read.All` | 1 | Entra |
| `Device.Read.All` | 1 | Entra (Extended) |
| `IdentityRiskyUser.Read.All` | 1 | Entra (P2) |
| `IdentityRiskyServicePrincipal.Read.All` | 1 | Entra (Workload ID Premium) |
| `Policy.Read.PermissionGrant` | 1 | Entra |
| `User.Read.All` | 1 | Entra (Extended) |
| `DeviceManagementConfiguration.Read.All` | 7 | Intune |
| `DeviceManagementApps.Read.All` | 3 | Intune |
| `DeviceManagementManagedDevices.Read.All` | 1 | Intune (Extended) |
| `DeviceManagementServiceConfig.Read.All` | 1 | Intune |
| `EntitlementManagement.Read.All` | 3 | Governance (P2) |
| `AccessReview.Read.All` | 1 | Governance (P2) |
| `Agreement.Read.All` | 1 | Governance |
| `PrivilegedAccess.Read.AzureADGroup` | 1 | Governance (P2) |
| `SecurityEvents.Read.All` | 2 | DefenderXdr |
| `CustomDetection.Read.All` | 1 | DefenderXdr |
| `SecurityAlert.Read.All` | 1 | DefenderXdr (Extended) |

**Azure RBAC** (not Graph — assign to the service principal on the resources): `Security Reader` (9 artifacts), `Microsoft Sentinel Reader` (7), `Reader` (6), and `Reader` at tenant root for `entra-diagnostic-settings`. `User Access Administrator` only if you want complete results from the Extended `azure-role-assignments` artifact.

**Defender for Endpoint API** — a separate resource (`WindowsDefenderATP`), not Microsoft Graph: `Score.Read.All` (2 artifacts), `SecurityRecommendation.Read.All` (1), `Ti.ReadWrite.All` (1).

> **On `Ti.ReadWrite.All`:** Microsoft's [List Indicators API](https://learn.microsoft.com/defender-endpoint/api/get-ti-indicators-collection) publishes no read-only permission; `Ti.ReadWrite` / `Ti.ReadWrite.All` is the only option for listing indicators. The script issues a `GET` and nothing else, but the granted scope is write-capable. If that is unacceptable for your engagement, omit it — `defender-indicators` will report `SkippedNoPermission` and the rest of the section still runs.

### Exchange and Purview: extra setup

The 60 artifacts in the `ExchangeOnline`, `DefenderOffice` and `Purview` sections run as PowerShell cmdlets, not Graph calls. Graph permissions do nothing for them. They need three things:

1. **Application permission `Exchange.ManageAsApp`** on the **Office 365 Exchange Online** API (not Microsoft Graph), with admin consent. Without it, `Connect-ExchangeOnline` app-only fails outright.
2. **An Entra directory role assigned to the service principal** — `Global Reader` covers all three sections read-only. Alternatively add the service principal to an Exchange role group for tighter scoping (`New-ServicePrincipal` + `Add-RoleGroupMember`).
3. **A certificate**, not a client secret. Exchange Online app-only has no client-secret path, which is why `-AuthMode ClientSecret` reports these sections as skipped.

> **Certificate gotcha:** Exchange app-only does not accept CNG certificates, which is what `New-SelfSignedCertificate` produces by default on modern Windows. The certificate must come from a CSP key provider — `New-SocAppRegistration.ps1` passes `-Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"` to force this. If you supply your own certificate, check it the same way. See [app-only authentication for Exchange Online PowerShell](https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2).

## Sections

Select with `-Include` / `-Exclude`. Counts are artifacts at `-Depth Extended`.

| Section | Artifacts | Covers |
|---|---|---|
| `Entra` | 38 | Conditional Access, named locations, authentication methods and strengths, security defaults, authorization and consent policy, cross-tenant access, domains and federation, directory roles and PIM, Identity Protection state |
| `Applications` | 6 | App registrations, service principals, delegated consent grants, application permissions, credential expiry |
| `Governance` | 6 | Access reviews, entitlement management, terms of use, PIM for Groups |
| `Intune` | 13 | Compliance policies and assignments, configuration profiles, settings catalog, endpoint security intents, enrollment restrictions, app protection |
| `DefenderXdr` | 8 | Secure Score and control profiles, custom detection rules, Defender for Endpoint indicators and exposure scores |
| `DefenderOffice` | 25 | Anti-phishing, anti-spam, anti-malware, Safe Links, Safe Attachments, preset policies, tenant allow/block list, phish-sim and SecOps overrides, quarantine, user reporting |
| `ExchangeOnline` | 23 | Organisation and audit config, transport rules, connectors, remote domains, authentication policies, mailbox audit bypass, role groups |
| `Purview` | 12 | Alert policies, audit configuration and retention, DLP, retention, sensitivity labels, communication compliance |
| `Azure` | 16 | Defender for Cloud plans, contacts, settings, suppression rules and automations; Azure Policy; Entra and subscription diagnostic settings; Log Analytics workspaces |
| `Sentinel` | 7 | Onboarded workspaces, analytics rules, data connectors, automation rules, settings, watchlists |

### Depth

`-Depth Standard` (default) collects configuration and runs in bounded time — typically a few minutes.

`-Depth Extended` adds 13 artifacts that scale with tenant size: per-application owners, per-principal app role assignments, guest accounts, Entra and Intune device inventories, Azure RBAC assignments, open alerts, and full per-user MFA registration detail. On a large tenant this can take considerably longer, since several of them issue one request per object.

## Output

```
soc-export/contoso.onmicrosoft.com_20260813-141530Z/
├── manifest.json          run metadata: tenant, timing, auth mode, selection, host, status counts
├── collection-log.json    per-artifact status, item count, duration, error
├── collection-log.csv     the same, for a spreadsheet
├── summary.md             posture highlights, gaps, and an index of what was collected
├── entra/                 one JSON file per artifact
├── applications/
├── intune/
├── defenderoffice/
└── ...
```

Every artifact file wraps its data with provenance, so an export is still interpretable months later:

```json
{
  "artifact": "conditional-access-policies",
  "domain": "Entra",
  "description": "All Conditional Access policies with conditions, grant and session controls...",
  "source": "Policy.Read.All",
  "tenantId": "11111111-2222-3333-4444-555555555555",
  "collectedUtc": "2026-08-13T14:15:31.4821930Z",
  "itemCount": 24,
  "redacted": false,
  "scriptVersion": "1.0.0",
  "value": [ ... ]
}
```

### Collection status

A failing collector never stops the run. Each artifact ends in one of:

| Status | Meaning |
|---|---|
| `Collected` | Data returned. |
| `Empty` | Call succeeded, nothing configured. A meaningful finding in its own right. |
| `SkippedNoPermission` | 401/403. The credential lacks the permission. |
| `SkippedNotLicensed` | Feature not licensed in this tenant (for example P2-only artifacts). |
| `SkippedNotFound` | Endpoint returned 404 — usually the feature is not enabled. |
| `SkippedNoTransport` | The required session could not be established (for example `ExchangeOnlineManagement` missing). |
| `Failed` | Something unexpected. Investigate before trusting the export as complete. |

`summary.md` lists every non-`Collected`/`Empty` artifact under **Gaps in this export**, and marks derived checks it could not evaluate as `Not collected` rather than passing them.

### Redaction

`-RedactUserData` replaces UPNs, mail addresses, phone numbers and personal name fields with per-run pseudonyms (`redacted-a1b2c3d4e5f6@redacted.invalid`). The same input maps to the same pseudonym **within one export**, so relationships stay analysable, and to a different one in the next export, so pseudonyms cannot be correlated across runs or reversed by comparison. Display names are preserved — configuration is unreadable without them.

## Operational notes

- **Throttling** is handled centrally: HTTP 429 and 5xx are retried with `Retry-After` when the service supplies it, exponential backoff otherwise (`-MaxRetryCount`, default 5).
- **Sovereign clouds** are supported with `-Environment USGov | USGovDoD | China`.
- **Diffing two exports** works well with the per-artifact JSON files, for example `git diff --no-index old/entra new/entra`, or `Compare-Object` on the parsed `value` arrays.
- **Scheduling**: run with `-AuthMode Certificate` and `-Archive`, and keep the archives. A monthly baseline makes drift obvious.

## Known limitations

Some settings have no API and cannot be exported by any script. This tool does not silently paper over them:

- **Self-service password reset policy** is not exposed through Graph; it remains portal-only.
- **Legacy Identity Protection user-risk and sign-in-risk policies** are not in Graph. Their replacements are Conditional Access policies, which *are* collected.
- **Defender XDR portal "Advanced features" toggles** have no public API.
- **Defender for Cloud Apps (MDA) policies** use a separate per-tenant API endpoint and are not covered.
- **Purview app-only support is uneven** — some compliance cmdlets still behave differently under certificate auth than under a delegated session. If a Purview artifact is unexpectedly empty, re-check it with `-AuthMode DeviceCode`.
- **This exports configuration, not telemetry.** Sign-in logs, audit logs and hunting results are investigation data — see the IAM ticket workflow document for those.

## Extending it

One artifact is one `Register-SocCollector` call. To add coverage, drop it into the relevant file under `collectors/`:

```powershell
Register-SocCollector -Name 'my-new-artifact' -Section 'Entra' -Transport 'Graph' `
    -Permission 'Policy.Read.All' `
    -Description 'What this is and why a SOC cares.' `
    -Script { Invoke-SocGraphRequest -Path '/policies/somethingNew' }
```

The runner handles transport setup, paging, throttling, error classification, persistence and reporting. Use `-Depth Extended` on the registration if the collector's cost scales with tenant size, and `Register-SocExchangeCollector` for anything that is a single Exchange or Compliance cmdlet.

### Layout

```
Export-SocTenantSettings.ps1   entry point: parameters, load, connect, run, report
private/
  Common.ps1                   logging, run context, artifact persistence, redaction
  Auth.ps1                     token acquisition (client secret, certificate JWT, device code)
  RestClient.ps1               Graph / ARM / Defender REST with paging and throttle retry
  ExchangeClient.ps1           Exchange Online and Security & Compliance sessions
  Registry.ps1                 collector manifest and runner
  Report.ps1                   manifest, collection log, summary and posture highlights
collectors/                    one file per section
```
