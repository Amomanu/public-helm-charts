<#
    DefenderXdr.ps1 — Microsoft Defender XDR posture and detection configuration.

    Split across two APIs: Microsoft Graph security endpoints for secure score
    and custom detection rules, and the Defender for Endpoint API for custom
    indicators and exposure scoring. The Defender API uses its own audience, so
    those collectors are reported separately when the app registration lacks
    Defender permissions.
#>

Set-StrictMode -Version Latest

Register-SocCollector -Name 'secure-score-latest' -Section 'DefenderXdr' -Transport 'Graph' `
    -Permission 'SecurityEvents.Read.All' `
    -Description 'Most recent Microsoft Secure Score snapshot with per-control scores and comparative averages.' `
    -Script { Invoke-SocGraphRequest -Path '/security/secureScores' -PageSize 1 -MaxItems 1 }

Register-SocCollector -Name 'secure-score-control-profiles' -Section 'DefenderXdr' -Transport 'Graph' `
    -Permission 'SecurityEvents.Read.All' `
    -Description 'Secure Score control definitions with tenant-specific state — which controls are ignored, planned or resolved by third party.' `
    -Script { Invoke-SocGraphRequest -Path '/security/secureScoreControlProfiles' -PageSize 500 }

Register-SocCollector -Name 'custom-detection-rules' -Section 'DefenderXdr' -Transport 'Graph' `
    -Permission 'CustomDetection.Read.All' `
    -Description 'Custom detection rules — the tenant-authored KQL detections running on Defender XDR advanced hunting data.' `
    -Script { Invoke-SocGraphRequest -Path '/security/rules/detectionRules' -ApiVersion 'beta' }

Register-SocCollector -Name 'defender-indicators' -Section 'DefenderXdr' -Transport 'Defender' `
    -Permission 'Ti.ReadWrite.All (Defender for Endpoint API)' `
    -Description 'Custom threat indicators (file hashes, IPs, URLs, certificates) and their alert/block actions.' `
    -Script { Invoke-SocDefenderRequest -Path '/api/indicators' }

Register-SocCollector -Name 'defender-exposure-score' -Section 'DefenderXdr' -Transport 'Defender' `
    -Permission 'Score.Read.All (Defender for Endpoint API)' `
    -Description 'Organisation exposure score from threat and vulnerability management.' `
    -Script { Invoke-SocDefenderRequest -Path '/api/exposureScore' -Single }

Register-SocCollector -Name 'defender-configuration-score' -Section 'DefenderXdr' -Transport 'Defender' `
    -Permission 'Score.Read.All (Defender for Endpoint API)' `
    -Description 'Microsoft Secure Score for Devices — endpoint configuration posture.' `
    -Script { Invoke-SocDefenderRequest -Path '/api/configurationScore' -Single }

Register-SocCollector -Name 'defender-recommendations' -Section 'DefenderXdr' -Transport 'Defender' -Depth 'Extended' `
    -Permission 'SecurityRecommendation.Read.All (Defender for Endpoint API)' `
    -Description 'Open security recommendations with affected device counts.' `
    -Script { Invoke-SocDefenderRequest -Path '/api/recommendations' }

Register-SocCollector -Name 'security-alerts-open' -Section 'DefenderXdr' -Transport 'Graph' -Depth 'Extended' `
    -Permission 'SecurityAlert.Read.All' `
    -Description 'Currently open Defender XDR alerts. Current state rather than configuration, included for baseline context.' `
    -Script {
    Invoke-SocGraphRequest -Path '/security/alerts_v2' -Filter "status eq 'new' or status eq 'inProgress'" -PageSize 200 -MaxItems 2000
}
