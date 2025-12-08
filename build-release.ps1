# Build and Release Script for GitHub Actions
# This script compiles MOF files and creates Machine Configuration packages for release

param(
    [Parameter(Mandatory = $false)]
    [string]$Version = "1.0.0",
    
    [Parameter(Mandatory = $false)]
    [switch]$UsePowerShell5,
    
    [Parameter(Mandatory = $false)]
    [switch]$ForcePowerShell7,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "./release"
)

$ErrorActionPreference = 'Stop'

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ACSC Windows Hardening - Build Release" -ForegroundColor Cyan
Write-Host "Version: $Version" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Install required modules if not present
Write-Host "`nChecking required PowerShell modules..." -ForegroundColor Yellow

$RequiredModules = @(
    @{ Name = 'GuestConfiguration'; MinVersion = '4.0.0' },
    @{ Name = 'PSDscResources'; MinVersion = '2.12.0' },
    @{ Name = 'SecurityPolicyDsc'; MinVersion = '2.10.0' },
    @{ Name = 'AuditPolicyDsc'; MinVersion = '1.4.0' },
    @{ Name = 'cChoco'; MinVersion = '2.6.0' },
    @{ Name = 'xPSDesiredStateConfiguration'; MinVersion = '9.1.0' }
)

foreach ($Module in $RequiredModules) {
    $ModuleName = $Module.Name
    $MinVersion = $Module.MinVersion
    
    try {
        $Installed = Get-Module -Name $ModuleName -ListAvailable | 
            Where-Object { $_.Version -ge [version]$MinVersion } | 
            Sort-Object Version -Descending | 
            Select-Object -First 1
        
        if ($Installed) {
            Write-Host "✅ $ModuleName v$($Installed.Version)" -ForegroundColor Green
        } else {
            Write-Host "📦 Installing $ModuleName..." -ForegroundColor Yellow
            Install-Module -Name $ModuleName -MinimumVersion $MinVersion -Force -AllowClobber -Scope CurrentUser -SkipPublisherCheck
            Write-Host "✅ $ModuleName installed" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "❌ Failed to install $ModuleName`: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Compile DSC configurations and create packages
Write-Host "`nCompiling DSC configurations..." -ForegroundColor Yellow

$ConfigurationLevels = @('HighPriority', 'MediumPriority')
$PackageFiles = @()

foreach ($Level in $ConfigurationLevels) {
    Write-Host "`nProcessing $Level configuration..." -ForegroundColor Cyan
    
    try {
        # Build package creation parameters
        $PackageParams = @{
            ConfigurationLevel = $Level
        }
        
        if ($UsePowerShell5) { $PackageParams.UsePowerShell5 = $true }
        if ($ForcePowerShell7) { $PackageParams.ForcePowerShell7 = $true }
        
        # Create the package
        $Result = & ./scripts/New-ACSCMachineConfigurationPackage.ps1 @PackageParams
        
        # Find the generated package file
        $PackageName = "ACSC$($Level)Hardening"
        $PackageFile = Get-ChildItem -Path "./packages" -Filter "$PackageName*.zip" -File | 
            Sort-Object LastWriteTime -Descending | 
            Select-Object -First 1
        
        if ($PackageFile) {
            # Copy to release directory
            $DestFile = Join-Path $OutputPath "$PackageName-v$Version.zip"
            Copy-Item -Path $PackageFile.FullName -Destination $DestFile -Force
            
            Write-Host "✅ Package created: $($PackageFile.Name)" -ForegroundColor Green
            Write-Host "   Size: $([math]::Round($PackageFile.Length / 1KB, 2)) KB" -ForegroundColor Gray
            
            # Calculate and save hash
            $Hash = (Get-FileHash -Path $DestFile -Algorithm SHA256).Hash
            $HashFile = "$DestFile.sha256"
            $Hash | Out-File -FilePath $HashFile -Encoding UTF8 -NoNewline
            
            Write-Host "   SHA256: $Hash" -ForegroundColor Gray
            
            $PackageFiles += @{
                Name = $PackageName
                File = $DestFile
                Hash = $Hash
                Size = $PackageFile.Length
            }
        } else {
            Write-Host "⚠️  Package file not found for $Level" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "❌ Failed to create $Level package: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host $_.Exception.StackTrace -ForegroundColor Red
        exit 1
    }
}

# Copy policy JSON files to release
Write-Host "`nCopying policy definitions..." -ForegroundColor Yellow

$PolicyFiles = Get-ChildItem -Path "./policies" -Filter "*.json" -File
foreach ($PolicyFile in $PolicyFiles) {
    $DestFile = Join-Path $OutputPath $PolicyFile.Name
    Copy-Item -Path $PolicyFile.FullName -Destination $DestFile -Force
    Write-Host "✅ Copied: $($PolicyFile.Name)" -ForegroundColor Green
}

# Create release notes
Write-Host "`nGenerating release notes..." -ForegroundColor Yellow

$ReleaseNotes = @"
# ACSC Windows Hardening v$Version

## 📦 Packages

"@

foreach ($Package in $PackageFiles) {
    $SizeKB = [math]::Round($Package.Size / 1KB, 2)
    $ReleaseNotes += @"

### $($Package.Name)
- **File**: ``$(Split-Path -Leaf $Package.File)``
- **Size**: $SizeKB KB
- **SHA256**: ``$($Package.Hash)``

"@
}

$ReleaseNotes += @"

## 📋 Policy Definitions

This release includes the following Azure Policy definitions:
- ``acsc-high-priority-policy.json`` - High Priority hardening controls
- ``acsc-medium-priority-policy.json`` - Medium Priority hardening controls

## 🚀 Deployment

### Quick Start

1. Download the packages and policy files
2. Upload packages to Azure Storage
3. Deploy policies using Azure Portal or CLI

### Azure CLI Deployment

``````powershell
# Set variables
`$subscriptionId = "your-subscription-id"
`$resourceGroup = "your-resource-group"
`$storageAccount = "your-storage-account"

# Deploy using the provided script
./scripts/Deploy-ACSCToAzure.ps1 \``
    -SubscriptionId `$subscriptionId \``
    -ResourceGroupName `$resourceGroup \``
    -StorageAccountName `$storageAccount
``````

## 📚 Documentation

- [Implementation Guide](./docs/implementation-guide.md)
- [Configuration Reference](./docs/configuration-reference.md)
- [ACSC Hardening Guidelines](https://www.cyber.gov.au/)

## ✅ What's Included

### High Priority Controls
- Password policies (14 character minimum)
- Account lockout policies
- Audit policies
- User rights assignments
- UAC settings
- Attack Surface Reduction (ASR) rules
- Credential protection
- BitLocker configuration
- Windows Defender settings
- PowerShell security logging

### Medium Priority Controls
- Extended password policies
- Screen saver/session locking
- RDP security hardening
- Network security settings
- Removable storage controls
- Firewall configuration
- Service hardening

## 🔧 Configuration Mode

Both configurations support **ApplyAndAutoCorrect** mode for automatic drift remediation:
- Checks compliance every 15 minutes
- Automatically corrects non-compliant settings
- Maintains security posture continuously

## 📝 Notes

- All Registry resources include ``Force = `$true`` to handle existing values
- Compatible with Windows Server 2016, 2019, 2022
- Requires Azure Machine Configuration extension
- Uses DirectResourceEngine for enhanced reliability

## 🐛 Known Issues

None reported for this release.

## 🤝 Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for contribution guidelines.

---

**Generated**: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")
**Build**: GitHub Actions
"@

$ReleaseNotesFile = Join-Path $OutputPath "RELEASE_NOTES.md"
$ReleaseNotes | Out-File -FilePath $ReleaseNotesFile -Encoding UTF8

Write-Host "✅ Release notes created: RELEASE_NOTES.md" -ForegroundColor Green

# Create artifact manifest
Write-Host "`nCreating artifact manifest..." -ForegroundColor Yellow

$Manifest = @{
    version = $Version
    buildDate = (Get-Date -Format "o")
    packages = @()
    policies = @()
}

foreach ($Package in $PackageFiles) {
    $Manifest.packages += @{
        name = $Package.Name
        file = Split-Path -Leaf $Package.File
        sha256 = $Package.Hash
        size = $Package.Size
    }
}

foreach ($PolicyFile in $PolicyFiles) {
    $Manifest.policies += @{
        name = $PolicyFile.BaseName
        file = $PolicyFile.Name
    }
}

$ManifestFile = Join-Path $OutputPath "manifest.json"
$Manifest | ConvertTo-Json -Depth 10 | Out-File -FilePath $ManifestFile -Encoding UTF8

Write-Host "✅ Manifest created: manifest.json" -ForegroundColor Green

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Build Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n📦 Release artifacts created in: $OutputPath" -ForegroundColor Green
Write-Host "`n📋 Files:" -ForegroundColor Yellow
Get-ChildItem -Path $OutputPath | ForEach-Object {
    $SizeMB = [math]::Round($_.Length / 1MB, 2)
    $SizeKB = [math]::Round($_.Length / 1KB, 2)
    $Size = if ($SizeMB -ge 1) { "$SizeMB MB" } else { "$SizeKB KB" }
    Write-Host "   - $($_.Name) ($Size)" -ForegroundColor Gray
}

Write-Host "`n✅ Ready for GitHub Release!" -ForegroundColor Green
