# Désactivation accès mobile Exchange (Online + On-Prem)

**Auteur :** ABOU SAYABOU  
**Script :** `Disable-ExchangeMobileAccess.ps1`

## Prérequis

### Exchange Online
```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```
Compte avec rôle **Exchange Administrator**.

### Exchange On-Premises
- Exchange 2016 / 2019
- Droits **Organization Management** (ou équivalent CAS)
- Soit lancer depuis **Exchange Management Shell**
- Soit Remote PowerShell vers le serveur (`-OnPremServer`)

## Paramètres principaux

| Paramètre | Description |
|-----------|-------------|
| `-Environment` | `Online` \| `OnPrem` \| `Both` |
| `-Users` | Liste UPN / SMTP / alias |
| `-CsvPath` | CSV (`UserPrincipalName` ou `PrimarySmtpAddress`) |
| `-AllMailboxes` | Toutes les boîtes utilisateur |
| `-OnPremServer` | FQDN serveur Exchange (ex. `mail.contoso.local`) |
| `-AlsoBlockOutlookMobile` | Coupe aussi Outlook iOS/Android |
| `-AlsoDisableOWA` | Coupe aussi Outlook Web |
| `-RemoveActiveSyncDevices` | Supprime les partenariats appareils existants |
| `-WhatIf` | Simulation |

## Exemples

```powershell
# Online — un utilisateur
.\Disable-ExchangeMobileAccess.ps1 -Environment Online `
  -Users "jean.dupont@contoso.com" -AlsoBlockOutlookMobile

# On-Prem — CSV
.\Disable-ExchangeMobileAccess.ps1 -Environment OnPrem `
  -OnPremServer mail.contoso.local `
  -CsvPath .\users.csv

# Hybride — les deux
.\Disable-ExchangeMobileAccess.ps1 -Environment Both `
  -OnPremServer mail.contoso.local `
  -Users "jean.dupont@contoso.com" `
  -AlsoBlockOutlookMobile `
  -RemoveActiveSyncDevices

# Simulation
.\Disable-ExchangeMobileAccess.ps1 -Environment Both `
  -OnPremServer mail.contoso.local `
  -Users "test@contoso.com" -WhatIf
```

## CSV exemple

```csv
UserPrincipalName
jean.dupont@contoso.com
marie.martin@contoso.com
```

## Réactiver l’accès mobile

```powershell
# Online / OnPrem (EMS)
Set-CASMailbox -Identity "jean.dupont@contoso.com" -ActiveSyncEnabled $true
Set-CASMailbox -Identity "jean.dupont@contoso.com" -OutlookMobileEnabled $true
```

## Notes hybrides

- En mode `Both`, le script traite **Online puis On-Prem** (déconnexion EXO entre les deux pour éviter les collisions de cmdlets).
- En hybride, l’utilisateur peut avoir une boîte d’un côté seulement : les erreurs « mailbox not found » sont normales sur l’autre environnement et apparaissent dans le CSV de rapport.
