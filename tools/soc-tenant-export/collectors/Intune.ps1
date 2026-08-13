<#
    Intune.ps1 — Microsoft Intune device and app management configuration.

    Conditional Access grant controls lean on device compliance, so the
    compliance policies themselves are part of the identity control surface.
#>

Set-StrictMode -Version Latest

Register-SocCollector -Name 'device-management-settings' -Section 'Intune' -Transport 'Graph' `
    -Permission 'DeviceManagementConfiguration.Read.All' `
    -Description 'Tenant-level Intune settings, including the device inactivity cleanup rule and enrollment defaults.' `
    -Script { Invoke-SocGraphRequest -Path '/deviceManagement' -Single }

Register-SocCollector -Name 'device-compliance-policies' -Section 'Intune' -Transport 'Graph' `
    -Permission 'DeviceManagementConfiguration.Read.All' `
    -Description 'Compliance policies that decide whether a device satisfies a Conditional Access "require compliant device" grant.' `
    -Script { Invoke-SocGraphRequest -Path '/deviceManagement/deviceCompliancePolicies' }

Register-SocCollector -Name 'device-compliance-policy-assignments' -Section 'Intune' -Transport 'Graph' `
    -Permission 'DeviceManagementConfiguration.Read.All' `
    -Description 'Group targeting for each compliance policy. An unassigned policy enforces nothing.' `
    -Script {
    $policies = Invoke-SocGraphRequest -Path '/deviceManagement/deviceCompliancePolicies'
    $output = [System.Collections.Generic.List[object]]::new()

    foreach ($policy in $policies) {
        $id = Get-SocProperty $policy 'id'
        try {
            $assignments = Invoke-SocGraphRequest -Path "/deviceManagement/deviceCompliancePolicies/$id/assignments"
        }
        catch {
            $assignments = @()
        }

        $output.Add([pscustomobject]@{
                policyId    = $id
                displayName = Get-SocProperty $policy 'displayName'
                odataType   = Get-SocProperty $policy '@odata.type'
                assignments = $assignments
            })
    }

    return $output.ToArray()
}

Register-SocCollector -Name 'device-configuration-profiles' -Section 'Intune' -Transport 'Graph' `
    -Permission 'DeviceManagementConfiguration.Read.All' `
    -Description 'Classic device configuration profiles.' `
    -Script { Invoke-SocGraphRequest -Path '/deviceManagement/deviceConfigurations' }

Register-SocCollector -Name 'configuration-policies' -Section 'Intune' -Transport 'Graph' `
    -Permission 'DeviceManagementConfiguration.Read.All' `
    -Description 'Settings catalog policies, which carry most current endpoint hardening including attack surface reduction rules.' `
    -Script { Invoke-SocGraphRequest -Path '/deviceManagement/configurationPolicies' -ApiVersion 'beta' }

Register-SocCollector -Name 'endpoint-security-intents' -Section 'Intune' -Transport 'Graph' `
    -Permission 'DeviceManagementConfiguration.Read.All' `
    -Description 'Endpoint security policies created from security baseline templates (antivirus, firewall, disk encryption, EDR).' `
    -Script { Invoke-SocGraphRequest -Path '/deviceManagement/intents' -ApiVersion 'beta' }

Register-SocCollector -Name 'device-enrollment-configurations' -Section 'Intune' -Transport 'Graph' `
    -Permission 'DeviceManagementServiceConfig.Read.All' `
    -Description 'Enrollment restrictions and platform limits — which device platforms may enrol at all.' `
    -Script { Invoke-SocGraphRequest -Path '/deviceManagement/deviceEnrollmentConfigurations' }

Register-SocCollector -Name 'app-protection-policies' -Section 'Intune' -Transport 'Graph' `
    -Permission 'DeviceManagementApps.Read.All' `
    -Description 'Mobile application management policies applied to corporate data on unmanaged devices.' `
    -Script { Invoke-SocGraphRequest -Path '/deviceAppManagement/managedAppPolicies' }

Register-SocCollector -Name 'managed-app-protection-ios' -Section 'Intune' -Transport 'Graph' `
    -Permission 'DeviceManagementApps.Read.All' `
    -Description 'iOS app protection policy detail, including data relocation and access requirements.' `
    -Script { Invoke-SocGraphRequest -Path '/deviceAppManagement/iosManagedAppProtections' }

Register-SocCollector -Name 'managed-app-protection-android' -Section 'Intune' -Transport 'Graph' `
    -Permission 'DeviceManagementApps.Read.All' `
    -Description 'Android app protection policy detail, including data relocation and access requirements.' `
    -Script { Invoke-SocGraphRequest -Path '/deviceAppManagement/androidManagedAppProtections' }

Register-SocCollector -Name 'mobile-threat-defense-connectors' -Section 'Intune' -Transport 'Graph' `
    -Permission 'DeviceManagementConfiguration.Read.All' `
    -Description 'Mobile threat defence connectors, including the Defender for Endpoint connector state.' `
    -Script { Invoke-SocGraphRequest -Path '/deviceManagement/mobileThreatDefenseConnectors' }

Register-SocCollector -Name 'conditional-access-device-settings' -Section 'Intune' -Transport 'Graph' `
    -Permission 'Policy.Read.All' `
    -Description 'Device registration policy — who may join or register devices, and whether MFA is required to do so.' `
    -Script { Invoke-SocGraphRequest -Path '/policies/deviceRegistrationPolicy' -ApiVersion 'beta' -Single }

Register-SocCollector -Name 'managed-devices' -Section 'Intune' -Transport 'Graph' -Depth 'Extended' `
    -Permission 'DeviceManagementManagedDevices.Read.All' `
    -Description 'Enrolled device inventory with compliance state, ownership and last check-in.' `
    -Script {
    Invoke-SocGraphRequest -Path '/deviceManagement/managedDevices' -PageSize 500 `
        -Select 'id,deviceName,operatingSystem,osVersion,complianceState,managedDeviceOwnerType,enrolledDateTime,lastSyncDateTime,azureADRegistered,deviceEnrollmentType,jailBroken,userPrincipalName'
}
