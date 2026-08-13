#!/usr/bin/env bash
#
# Creates the app registration used by Export-SocTenantSettings.ps1.
#
# Permission IDs are looked up from each resource service principal at run time
# rather than hardcoded, so this does not rot when Microsoft adds or renames
# scopes, and it fails loudly instead of silently granting the wrong GUID.
#
# Requires: az CLI, openssl, and an account that can create app registrations
# and grant admin consent (Global Administrator, or Application Administrator
# plus Privileged Role Administrator).
#
# Usage (TENANT_ID is required and is verified against the signed-in tenant):
#   TENANT_ID=contoso.onmicrosoft.com ./new-soc-app-registration.sh
#   TENANT_ID=contoso.onmicrosoft.com SECTIONS=entra ./new-soc-app-registration.sh
#   TENANT_ID=contoso.onmicrosoft.com TENANT_ROOT_SCOPE=1 ./new-soc-app-registration.sh

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

APP_NAME="${APP_NAME:-SOC Tenant Settings Export}"
CERT_DIR="${CERT_DIR:-./soc-export-cert}"
CERT_DAYS="${CERT_DAYS:-730}"

# all | entra — "entra" grants only what the Entra/Applications sections need.
SECTIONS="${SECTIONS:-all}"

# The tenant to provision in, as a GUID or verified domain. Required, and
# checked against the tenant az is signed in to.
TENANT_ID="${TENANT_ID:-}"

# Set to 1 to also grant Reader and Security Reader at the tenant root
# management group, which every subscription inherits from. Needed for the Azure
# and Sentinel sections; requires a Global Administrator to have elevated access.
TENANT_ROOT_SCOPE="${TENANT_ROOT_SCOPE:-}"

# Directory role granted to the service principal. Required for the Exchange,
# Defender for Office 365 and Purview sections; harmless otherwise.
DIRECTORY_ROLE="${DIRECTORY_ROLE:-Global Reader}"

# Well-known first-party resource app IDs.
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"
EXO_APP_ID="00000002-0000-0ff1-ce00-000000000000"     # Office 365 Exchange Online
MDE_APP_ID="fc780465-2017-40d4-a0c5-307022471b92"     # WindowsDefenderATP

# ---------------------------------------------------------------------------
# Permission sets
# ---------------------------------------------------------------------------

GRAPH_PERMISSIONS_CORE=(
  Organization.Read.All
  Directory.Read.All
  Domain.Read.All
  Policy.Read.All
  Policy.Read.AuthenticationMethod
  Policy.Read.PermissionGrant
  RoleManagement.Read.Directory
  AdministrativeUnit.Read.All
  Application.Read.All
  AuditLog.Read.All
  User.Read.All
  Device.Read.All
  IdentityRiskyUser.Read.All
  IdentityRiskyServicePrincipal.Read.All
)

GRAPH_PERMISSIONS_FULL=(
  DeviceManagementConfiguration.Read.All
  DeviceManagementApps.Read.All
  DeviceManagementServiceConfig.Read.All
  DeviceManagementManagedDevices.Read.All
  AccessReview.Read.All
  EntitlementManagement.Read.All
  Agreement.Read.All
  PrivilegedAccess.Read.AzureADGroup
  SecurityEvents.Read.All
  SecurityAlert.Read.All
  CustomDetection.Read.All
)

# Ti.ReadWrite.All is the only permission the List Indicators API accepts —
# Microsoft publishes no read-only variant. Drop it if a write-capable scope is
# unacceptable; only the defender-indicators artifact is lost.
MDE_PERMISSIONS=(Score.Read.All SecurityRecommendation.Read.All Ti.ReadWrite.All)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m ! \033[0m %s\n' "$*"; }
die()  { printf '\033[31mERR\033[0m %s\n' "$*" >&2; exit 1; }

# Ensures the resource service principal exists in this tenant, so its appRoles
# can be enumerated. Returns non-zero if the resource is not available.
ensure_resource_sp() {
  local app_id="$1"
  if az ad sp show --id "$app_id" >/dev/null 2>&1; then
    return 0
  fi
  az ad sp create --id "$app_id" >/dev/null 2>&1 || return 1
}

# Resolves an application permission name to its appRole GUID.
role_id_for() {
  local resource_app_id="$1" permission="$2" id
  id=$(az ad sp show --id "$resource_app_id" \
        --query "appRoles[?value=='${permission}' && contains(allowedMemberTypes,'Application')].id | [0]" \
        -o tsv 2>/dev/null || true)
  [[ -n "$id" && "$id" != "None" ]] || return 1
  printf '%s' "$id"
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

command -v az >/dev/null || die "az CLI not found."
command -v openssl >/dev/null || die "openssl not found."
[[ -n "$TENANT_ID" ]] || die "TENANT_ID is required. Example: TENANT_ID=contoso.onmicrosoft.com $0"

az account show >/dev/null 2>&1 || die "Not signed in. Run: az login --tenant $TENANT_ID --allow-no-subscriptions"

SIGNED_IN_TENANT=$(az account show --query tenantId -o tsv)
SIGNED_IN_DOMAIN=$(az rest --method GET --url "https://graph.microsoft.com/v1.0/domains" \
  --query "value[?isInitial].id | [0]" -o tsv 2>/dev/null || echo "")
[[ "$SIGNED_IN_DOMAIN" == "None" ]] && SIGNED_IN_DOMAIN=""

# Everything here is directory-scoped and hard to walk back — an app
# registration, admin consent, a directory role. Confirm the signed-in tenant is
# the one that was asked for rather than whichever tenant a stale az login
# points at, which is how an MSP provisions into the wrong customer.
if [[ "$TENANT_ID" != "$SIGNED_IN_TENANT" && "$TENANT_ID" != "$SIGNED_IN_DOMAIN" ]]; then
  die "Refusing to act: az is signed in to $SIGNED_IN_TENANT ($SIGNED_IN_DOMAIN), not $TENANT_ID.
     Sign in to the intended tenant:  az login --tenant $TENANT_ID --allow-no-subscriptions"
fi

TENANT_ID="$SIGNED_IN_TENANT"
PRIMARY_DOMAIN="${SIGNED_IN_DOMAIN:-$TENANT_ID}"
log "Tenant: $PRIMARY_DOMAIN ($TENANT_ID)"

# ---------------------------------------------------------------------------
# App registration and service principal
# ---------------------------------------------------------------------------

APP_ID=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv 2>/dev/null || true)

if [[ -n "$APP_ID" && "$APP_ID" != "None" ]]; then
  warn "Reusing existing app registration '$APP_NAME' ($APP_ID)"
else
  log "Creating app registration '$APP_NAME'"
  APP_ID=$(az ad app create --display-name "$APP_NAME" \
            --sign-in-audience AzureADMyOrg --query appId -o tsv)
fi

az ad sp show --id "$APP_ID" >/dev/null 2>&1 || az ad sp create --id "$APP_ID" >/dev/null
SP_OBJECT_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv)
log "Service principal object ID: $SP_OBJECT_ID"

# ---------------------------------------------------------------------------
# Microsoft Graph permissions
# ---------------------------------------------------------------------------

GRAPH_PERMISSIONS=("${GRAPH_PERMISSIONS_CORE[@]}")
if [[ "$SECTIONS" == "all" ]]; then
  GRAPH_PERMISSIONS+=("${GRAPH_PERMISSIONS_FULL[@]}")
fi

ensure_resource_sp "$GRAPH_APP_ID" || die "Microsoft Graph service principal unavailable."

log "Resolving ${#GRAPH_PERMISSIONS[@]} Microsoft Graph permissions"
GRAPH_ARGS=()
for permission in "${GRAPH_PERMISSIONS[@]}"; do
  if role_guid=$(role_id_for "$GRAPH_APP_ID" "$permission"); then
    GRAPH_ARGS+=("${role_guid}=Role")
  else
    warn "Graph permission not found, skipping: $permission"
  fi
done

# One call for all of them — az writes requiredResourceAccess wholesale, so
# adding them individually would be both slower and racier.
[[ ${#GRAPH_ARGS[@]} -gt 0 ]] &&
  az ad app permission add --id "$APP_ID" --api "$GRAPH_APP_ID" \
    --api-permissions "${GRAPH_ARGS[@]}" --only-show-errors >/dev/null

# ---------------------------------------------------------------------------
# Office 365 Exchange Online — Exchange.ManageAsApp
# ---------------------------------------------------------------------------
# Without this the Exchange, Defender for Office 365 and Purview sections (60
# artifacts) cannot connect at all. It lives on a different resource from Graph.

if [[ "$SECTIONS" == "all" ]]; then
  if ensure_resource_sp "$EXO_APP_ID" && exo_guid=$(role_id_for "$EXO_APP_ID" "Exchange.ManageAsApp"); then
    log "Adding Exchange.ManageAsApp"
    az ad app permission add --id "$APP_ID" --api "$EXO_APP_ID" \
      --api-permissions "${exo_guid}=Role" --only-show-errors >/dev/null
  else
    warn "Exchange.ManageAsApp unavailable — Exchange/DefenderOffice/Purview sections will be skipped."
  fi
fi

# ---------------------------------------------------------------------------
# Defender for Endpoint API
# ---------------------------------------------------------------------------

if [[ "$SECTIONS" == "all" ]]; then
  if ensure_resource_sp "$MDE_APP_ID"; then
    MDE_ARGS=()
    for permission in "${MDE_PERMISSIONS[@]}"; do
      if role_guid=$(role_id_for "$MDE_APP_ID" "$permission"); then
        MDE_ARGS+=("${role_guid}=Role")
      else
        warn "Defender permission not found, skipping: $permission"
      fi
    done
    if [[ ${#MDE_ARGS[@]} -gt 0 ]]; then
      log "Adding ${#MDE_ARGS[@]} Defender for Endpoint permissions"
      az ad app permission add --id "$APP_ID" --api "$MDE_APP_ID" \
        --api-permissions "${MDE_ARGS[@]}" --only-show-errors >/dev/null
    fi
  else
    warn "WindowsDefenderATP not present in this tenant — Defender API artifacts will be skipped."
  fi
fi

# ---------------------------------------------------------------------------
# Admin consent
# ---------------------------------------------------------------------------

log "Granting admin consent (needs Global Administrator or Privileged Role Administrator)"
sleep 10   # replication delay: consent against a just-written app often 404s
if ! az ad app permission admin-consent --id "$APP_ID" 2>/dev/null; then
  warn "Admin consent failed. Grant it in the portal: Entra ID > App registrations > $APP_NAME > API permissions"
fi

# ---------------------------------------------------------------------------
# Certificate
# ---------------------------------------------------------------------------
# Generated with openssl rather than New-SelfSignedCertificate: Exchange
# app-only rejects CNG certificates, which is what Windows creates by default.

mkdir -p "$CERT_DIR"
if [[ -f "$CERT_DIR/soc-export.pfx" ]]; then
  warn "Reusing existing certificate in $CERT_DIR"
else
  log "Generating certificate (valid $CERT_DAYS days)"
  openssl req -x509 -newkey rsa:2048 -sha256 -days "$CERT_DAYS" -nodes \
    -keyout "$CERT_DIR/soc-export.key" -out "$CERT_DIR/soc-export.crt" \
    -subj "/CN=${APP_NAME}" >/dev/null 2>&1

  openssl pkcs12 -export -out "$CERT_DIR/soc-export.pfx" \
    -inkey "$CERT_DIR/soc-export.key" -in "$CERT_DIR/soc-export.crt" \
    -passout pass: >/dev/null 2>&1

  chmod 600 "$CERT_DIR"/soc-export.*
  az ad app credential reset --id "$APP_ID" --cert "@$CERT_DIR/soc-export.crt" \
    --append --years "$((CERT_DAYS / 365 + 1))" --only-show-errors >/dev/null
fi

THUMBPRINT=$(openssl x509 -in "$CERT_DIR/soc-export.crt" -noout -fingerprint -sha1 |
             sed 's/.*=//; s/://g')

# ---------------------------------------------------------------------------
# Directory role (required for Exchange / Purview)
# ---------------------------------------------------------------------------

if [[ "$SECTIONS" == "all" ]]; then
  log "Assigning directory role '$DIRECTORY_ROLE' to the service principal"
  ROLE_DEF_ID=$(az rest --method GET \
    --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?\$filter=displayName eq '${DIRECTORY_ROLE}'" \
    --query "value[0].id" -o tsv 2>/dev/null || true)

  if [[ -n "$ROLE_DEF_ID" && "$ROLE_DEF_ID" != "None" ]]; then
    az rest --method POST \
      --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
      --headers "Content-Type=application/json" \
      --body "{\"@odata.type\":\"#microsoft.graph.unifiedRoleAssignment\",\"roleDefinitionId\":\"${ROLE_DEF_ID}\",\"principalId\":\"${SP_OBJECT_ID}\",\"directoryScopeId\":\"/\"}" \
      >/dev/null 2>&1 && log "Directory role assigned" ||
      warn "Directory role assignment failed (it may already exist, or you lack Privileged Role Administrator)."
  else
    warn "Directory role '$DIRECTORY_ROLE' not found."
  fi
fi

# ---------------------------------------------------------------------------
# Azure RBAC
# ---------------------------------------------------------------------------

# The root management group carries the tenant's own ID, and every subscription
# in the directory inherits from it — including ones created after this runs. One
# assignment here is the tenant-shaped equivalent of enumerating subscriptions.
ROOT_MG_SCOPE="/providers/Microsoft.Management/managementGroups/$TENANT_ID"
AZURE_ROLES_ASSIGNED=""

if [[ -n "$TENANT_ROOT_SCOPE" ]]; then
  log "Assigning Azure roles at the tenant root management group"
  for role in "Reader" "Security Reader"; do
    if az role assignment create --assignee-object-id "$SP_OBJECT_ID" \
        --assignee-principal-type ServicePrincipal --role "$role" \
        --scope "$ROOT_MG_SCOPE" --only-show-errors >/dev/null 2>&1; then
      log "  $role"
      AZURE_ROLES_ASSIGNED=1
    else
      warn "  $role assignment failed — it may already exist, or you lack access to the root management group."
      warn "  A Global Administrator must elevate access first: Entra ID > Properties > Access management for Azure resources."
    fi
  done
else
  warn "TENANT_ROOT_SCOPE not set — Azure and Sentinel sections will be skipped."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

cat <<SUMMARY

$(printf '\033[32m%s\033[0m' 'App registration ready.')

  Application (client) ID : $APP_ID
  Service principal       : $SP_OBJECT_ID
  Tenant                  : $PRIMARY_DOMAIN ($TENANT_ID)
  Certificate             : $CERT_DIR/soc-export.pfx
  Thumbprint              : $THUMBPRINT

Verify the grant took effect before the first real run:

  ./Export-SocTenantSettings.ps1 -ListArtifacts | Format-Table Section,Name,Permission

Then run the export:

  ./Export-SocTenantSettings.ps1 \\
      -TenantId $PRIMARY_DOMAIN \\
      -AuthMode Certificate \\
      -ClientId $APP_ID \\
      -CertificatePath $CERT_DIR/soc-export.pfx

Still to do by hand:${AZURE_ROLES_ASSIGNED:+
  (Azure RBAC already granted at the tenant root management group.)}${AZURE_ROLES_ASSIGNED:-
  * Azure RBAC for the Azure and Sentinel sections. Graph permissions grant
    nothing over Azure resources, so those sections stay skipped until this is
    in place. Re-run with TENANT_ROOT_SCOPE=1, or:
      az role assignment create --assignee-object-id $SP_OBJECT_ID \\
          --assignee-principal-type ServicePrincipal --role Reader \\
          --scope $ROOT_MG_SCOPE}
  * Microsoft Sentinel Reader on any Sentinel workspace you want collected.
  * On Windows, import the PFX with a CSP provider — Exchange app-only rejects
    CNG certificates:
      certutil -importpfx -csp "Microsoft Enhanced RSA and AES Cryptographic Provider" \\
        $CERT_DIR/soc-export.pfx

SUMMARY
