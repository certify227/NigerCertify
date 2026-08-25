<#
.SYNOPSIS
  Désactive l'accès mobile Exchange (ActiveSync / Outlook Mobile)
  pour Exchange Online et/ou Exchange On-Premises.

.DESCRIPTION
  Script unique hybride :
    - Online  : module ExchangeOnlineManagement
    - OnPrem  : session EMS / Remote PowerShell vers le serveur Exchange
    - Both    : exécute les deux environnements (scénario hybride)

  Actions possibles :
    - ActiveSyncEnabled = $false
    - OutlookMobileEnabled / OWAforDevicesEnabled = $false (si supporté)
    - OWAEnabled = $false (optionnel, accès web)

.NOTES
  Auteur     : ABOU SAYABOU
  Version    : 1.0
  Compatible : Exchange 2016/2019 + Exchange Online (Microsoft 365)

.EXAMPLE
  .\Disable-ExchangeMobileAccess.ps1 -Environment Online -Users "jean@contoso.com"

.EXAMPLE
  .\Disable-ExchangeMobileAccess.ps1 -Environment OnPrem -CsvPath .\users.csv -OnPremServer mail.contoso.local

.EXAMPLE
  .\Disable-ExchangeMobileAccess.ps1 -Environment Both -Users "jean@contoso.com" `
      -OnPremServer mail.contoso.local -AlsoBlockOutlookMobile -WhatIf
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Environnement cible
    [Parameter(Mandatory = $true)]
    [ValidateSet("Online", "OnPrem", "Both")]
    [string]$Environment,

    # Cibles
    [Parameter(Mandatory = $false)]
    [string[]]$Users,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$AllMailboxes,

    # On-Premises
    [Parameter(Mandatory = $false)]
    [string]$OnPremServer,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$OnPremCredential,

    [Parameter(Mandatory = $false)]
    [string]$OnPremUri,
    # Ex: http://mail.contoso.local/PowerShell/

    # Options fonctionnelles
    [Parameter(Mandatory = $false)]
    [switch]$AlsoBlockOutlookMobile,

    [Parameter(Mandatory = $false)]
    [switch]$AlsoDisableOWA,

    [Parameter(Mandatory = $false)]
    [switch]$RemoveActiveSyncDevices,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\Disable-MobileAccess_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =============================================================================
# Fonctions utilitaires
# =============================================================================

function Write-Info([string]$Message) {
    Write-Host "[INFO]  $Message" -ForegroundColor Cyan
}
function Write-Ok([string]$Message) {
    Write-Host "[OK]    $Message" -ForegroundColor Green
}
function Write-WarnMsg([string]$Message) {
    Write-Host "[WARN]  $Message" -ForegroundColor Yellow
}
function Write-Err([string]$Message) {
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Get-TargetList {
    $list = New-Object System.Collections.Generic.List[string]

    if ($CsvPath) {
        if (-not (Test-Path -LiteralPath $CsvPath)) {
            throw "CSV introuvable : $CsvPath"
        }
        $rows = Import-Csv -LiteralPath $CsvPath
        $col = @("UserPrincipalName", "UPN", "Identity", "Email", "PrimarySmtpAddress", "Alias") |
            Where-Object { $_ -in $rows[0].PSObject.Properties.Name } |
            Select-Object -First 1

        if (-not $col) {
            throw "Le CSV doit contenir une colonne UserPrincipalName, Identity, Email ou PrimarySmtpAddress."
        }
        foreach ($r in $rows) {
            $v = [string]$r.$col
            if (-not [string]::IsNullOrWhiteSpace($v)) { $list.Add($v.Trim()) }
        }
    }

    if ($Users) {
        foreach ($u in $Users) {
            if (-not [string]::IsNullOrWhiteSpace($u)) { $list.Add($u.Trim()) }
        }
    }

    return ($list | Select-Object -Unique)
}

function Connect-Exo {
    Write-Info "Connexion Exchange Online..."
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        throw "Module ExchangeOnlineManagement manquant. Installez : Install-Module ExchangeOnlineManagement -Scope CurrentUser"
    }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    Connect-ExchangeOnline -ShowBanner:$false
    Write-Ok "Connecté à Exchange Online."
}

function Connect-OnPrem {
    if (-not $OnPremServer -and -not $OnPremUri) {
        throw "Pour OnPrem, précisez -OnPremServer (ex: mail.contoso.local) ou -OnPremUri."
    }

    # Déjà dans EMS ?
    if (Get-Command Get-CASMailbox -ErrorAction SilentlyContinue) {
        Write-Ok "Session Exchange On-Prem déjà disponible (EMS)."
        return $null
    }

    $uri = if ($OnPremUri) {
        $OnPremUri
    }
    else {
        "http://$OnPremServer/PowerShell/"
    }

    Write-Info "Ouverture session Remote PowerShell On-Prem : $uri"
    $sessionParams = @{
        ConfigurationName = "Microsoft.Exchange"
        ConnectionUri     = $uri
        Authentication    = "Kerberos"
        AllowRedirection  = $true
    }
    if ($OnPremCredential) {
        $sessionParams["Credential"] = $OnPremCredential
        $sessionParams["Authentication"] = "Default"
    }

    $session = New-PSSession @sessionParams
    Import-PSSession $session -DisableNameChecking -AllowClobber | Out-Null
    Write-Ok "Connecté à Exchange On-Premises."
    return $session
}

function Get-AllMailboxIdentities {
    param([ValidateSet("Online", "OnPrem")][string]$EnvName)

    Write-Info "Récupération de toutes les boîtes ($EnvName)..."
    if ($EnvName -eq "Online") {
        return (Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox).UserPrincipalName
    }
    else {
        return (Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox).PrimarySmtpAddress
    }
}

function Disable-MobileForUser {
    param(
        [Parameter(Mandatory = $true)][string]$Identity,
        [Parameter(Mandatory = $true)][ValidateSet("Online", "OnPrem")][string]$EnvName
    )

    $row = [ordered]@{
        Environment             = $EnvName
        Identity                = $Identity
        ActiveSyncBefore        = $null
        ActiveSyncAfter         = $null
        OutlookMobileBefore     = $null
        OutlookMobileAfter      = $null
        OWABefore               = $null
        OWAAfter                = $null
        DevicesRemoved          = 0
        Status                  = "OK"
        Message                 = ""
    }

    try {
        $cas = Get-CASMailbox -Identity $Identity -ErrorAction Stop
        $row.ActiveSyncBefore = $cas.ActiveSyncEnabled
        $row.OWABefore = $cas.OWAEnabled

        # Propriétés Outlook Mobile / OWA for Devices selon version
        $hasOutlookMobile = $cas.PSObject.Properties.Name -contains "OutlookMobileEnabled"
        $hasOwaDevices    = $cas.PSObject.Properties.Name -contains "OWAforDevicesEnabled"
        if ($hasOutlookMobile) { $row.OutlookMobileBefore = $cas.OutlookMobileEnabled }
        elseif ($hasOwaDevices) { $row.OutlookMobileBefore = $cas.OWAforDevicesEnabled }

        $setParams = @{
            Identity           = $Identity
            ActiveSyncEnabled  = $false
            ErrorAction        = "Stop"
        }

        if ($AlsoBlockOutlookMobile) {
            if ($hasOutlookMobile) {
                $setParams["OutlookMobileEnabled"] = $false
            }
            elseif ($hasOwaDevices) {
                $setParams["OWAforDevicesEnabled"] = $false
            }
            else {
                Write-WarnMsg "$Identity ($EnvName) : propriété Outlook Mobile / OWAforDevices indisponible sur cette version."
            }
        }

        if ($AlsoDisableOWA) {
            $setParams["OWAEnabled"] = $false
        }

        if ($PSCmdlet.ShouldProcess("$Identity [$EnvName]", "Désactiver accès mobile Exchange")) {
            Set-CASMailbox @setParams

            # Révoquer les partenariats ActiveSync existants (optionnel)
            if ($RemoveActiveSyncDevices) {
                $devices = @(Get-MobileDeviceStatistics -Mailbox $Identity -ErrorAction SilentlyContinue)
                foreach ($d in $devices) {
                    try {
                        # Online / récent
                        if (Get-Command Remove-MobileDevice -ErrorAction SilentlyContinue) {
                            Remove-MobileDevice -Identity $d.Guid -Confirm:$false -ErrorAction SilentlyContinue
                        }
                        # OnPrem classique
                        elseif (Get-Command Clear-ActiveSyncDevice -ErrorAction SilentlyContinue) {
                            Clear-ActiveSyncDevice -Identity $d.Guid -Confirm:$false -ErrorAction SilentlyContinue
                        }
                        $row.DevicesRemoved++
                    }
                    catch {
                        Write-WarnMsg "Device non retiré ($Identity) : $($_.Exception.Message)"
                    }
                }
            }

            $cas2 = Get-CASMailbox -Identity $Identity -ErrorAction Stop
            $row.ActiveSyncAfter = $cas2.ActiveSyncEnabled
            $row.OWAAfter = $cas2.OWAEnabled
            if ($cas2.PSObject.Properties.Name -contains "OutlookMobileEnabled") {
                $row.OutlookMobileAfter = $cas2.OutlookMobileEnabled
            }
            elseif ($cas2.PSObject.Properties.Name -contains "OWAforDevicesEnabled") {
                $row.OutlookMobileAfter = $cas2.OWAforDevicesEnabled
            }

            Write-Ok "$EnvName :: $Identity → ActiveSync=$($row.ActiveSyncAfter)"
        }
        else {
            $row.Status = "WhatIf"
            $row.Message = "Simulation uniquement"
            $row.ActiveSyncAfter = $false
        }
    }
    catch {
        $row.Status = "ERROR"
        $row.Message = $_.Exception.Message
        Write-Err "$EnvName :: $Identity → $($_.Exception.Message)"
    }

    return [pscustomobject]$row
}

function Invoke-EnvironmentPass {
    param(
        [ValidateSet("Online", "OnPrem")][string]$EnvName,
        [string[]]$TargetUsers
    )

    $identities = @()
    if ($AllMailboxes -and -not $TargetUsers) {
        $identities = Get-AllMailboxIdentities -EnvName $EnvName
    }
    else {
        $identities = $TargetUsers
    }

    if (-not $identities -or $identities.Count -eq 0) {
        Write-WarnMsg "Aucune cible pour $EnvName."
        return @()
    }

    Write-Info "$EnvName : $($identities.Count) utilisateur(s) à traiter."
    $out = foreach ($id in $identities) {
        Disable-MobileForUser -Identity $id -EnvName $EnvName
    }
    return $out
}

# =============================================================================
# Main
# =============================================================================

Write-Host ""
Write-Host "=== Disable Exchange Mobile Access ===" -ForegroundColor White
Write-Host "Environnement : $Environment" -ForegroundColor White
Write-Host ""

$targets = Get-TargetList
if (-not $AllMailboxes -and (-not $targets -or $targets.Count -eq 0)) {
    throw "Indiquez -Users, -CsvPath ou -AllMailboxes."
}

$allResults = New-Object System.Collections.Generic.List[object]
$onPremSession = $null

try {
    # --- ONLINE ---
    if ($Environment -in @("Online", "Both")) {
        Connect-Exo
        $rOnline = Invoke-EnvironmentPass -EnvName "Online" -TargetUsers $targets
        foreach ($r in $rOnline) { $allResults.Add($r) }
    }

    # --- ON-PREM ---
    # Si Both : on se déconnecte d'EXO pour éviter les conflits de cmdlets, puis OnPrem
    if ($Environment -eq "Both") {
        Write-Info "Basculé vers On-Premises (déconnexion EXO pour éviter les collisions de commandes)..."
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" } |
            Remove-PSSession -ErrorAction SilentlyContinue
    }

    if ($Environment -in @("OnPrem", "Both")) {
        $onPremSession = Connect-OnPrem
        $rOnPrem = Invoke-EnvironmentPass -EnvName "OnPrem" -TargetUsers $targets
        foreach ($r in $rOnPrem) { $allResults.Add($r) }
    }
}
finally {
    # Nettoyage sessions
    if ($Environment -in @("Online", "Both")) {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($onPremSession) {
        Remove-PSSession -Session $onPremSession -ErrorAction SilentlyContinue
    }
}

# Rapport
$allResults | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Info "Rapport exporté : $((Resolve-Path $ReportPath).Path)"

$ok  = @($allResults | Where-Object Status -eq "OK").Count
$err = @($allResults | Where-Object Status -eq "ERROR").Count
$wif = @($allResults | Where-Object Status -eq "WhatIf").Count
Write-Host "Résumé → OK=$ok | ERROR=$err | WhatIf=$wif | Total=$($allResults.Count)" -ForegroundColor White

if ($err -gt 0) { exit 1 } else { exit 0 }
