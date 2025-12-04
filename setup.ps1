# Quick Setup Script for ACSC Windows Hardening
# This script provides a quick way to get started with the ACSC Windows Hardening project

param(
    [Parameter(Mandatory = $false)]
    [switch]$InstallModules,
    
    [Parameter(Mandatory = $false)]
    [switch]$CreatePackages,
    
    [Parameter(Mandatory = $false)]
    [switch]$UsePowerShell5,
    
    [Parameter(Mandatory = $false)]
    [switch]$ForcePowerShell7,
    
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $false)]
    [string]$StorageAccountName,
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$ServicePrincipalId,
    
    [Parameter(Mandatory = $false)]
    [securestring]$ServicePrincipalSecret
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ACSC Windows Hardening Quick Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "This script should be run as Administrator for best results."
}

# Check for Windows Security Baseline dependency
Write-Host "`nChecking Windows Security Baseline dependency..." -ForegroundColor Yellow

$BaselineInstalled = $false
$PolicyPath = "$env:SystemRoot\PolicyDefinitions"

# Check for some key policy templates that come with the security baseline
$BaselineTemplates = @(
    'MSS-legacy.admx',
    'MSSecurityGuide.admx'
)

foreach ($Template in $BaselineTemplates) {
    if (Test-Path (Join-Path $PolicyPath $Template)) {
        $BaselineInstalled = $true
        break
    }
}

if ($BaselineInstalled) {
    Write-Host "✅ Windows Security Baseline templates detected" -ForegroundColor Green
} else {
    Write-Host "⚠️  Windows Security Baseline templates not found" -ForegroundColor Red
    Write-Host "   ACSC configurations require Windows Security Baseline policy templates" -ForegroundColor Yellow
    Write-Host "   Download from: https://www.microsoft.com/download/details.aspx?id=55319" -ForegroundColor Yellow
    Write-Host "   Install the Security Compliance Toolkit and extract the policy templates" -ForegroundColor Yellow
    
    # $continue = Read-Host "`nContinue anyway? (y/N)"
    # if ($continue -ne 'y' -and $continue -ne 'Y') {
    #     Write-Host "Setup cancelled. Please install Windows Security Baseline templates first." -ForegroundColor Red
    #     exit 1
    # }
}

# Install required modules
if ($InstallModules) {
    Write-Host "`nInstalling required PowerShell modules..." -ForegroundColor Yellow
    
    $RequiredModules = @(
        'Az.Accounts',
        'Az.Resources', 
        'Az.Storage',
        'Az.PolicyInsights',
        'GuestConfiguration',
        'PSDscResources',
        'SecurityPolicyDsc',
        'AuditPolicyDsc',
        'ComputerManagementDsc'
    )
    
    foreach ($Module in $RequiredModules) {
        try {
            Write-Host "Installing $Module..." -ForegroundColor Gray
            
            # Check if module is already installed
            $InstalledVersions = Get-Module -Name $Module -ListAvailable | Sort-Object Version -Descending
            
            if ($InstalledVersions) {
                $LatestInstalled = $InstalledVersions[0].Version
                Write-Host "  Currently installed: $LatestInstalled" -ForegroundColor Gray
                
                # Check for updates
                $OnlineVersion = Find-Module -Name $Module -ErrorAction SilentlyContinue
                if ($OnlineVersion -and $OnlineVersion.Version -gt $LatestInstalled) {
                    Write-Host "  Update available: $($OnlineVersion.Version)" -ForegroundColor Yellow
                    Install-Module -Name $Module -RequiredVersion $OnlineVersion.Version -Force -AllowClobber -Scope CurrentUser -SkipPublisherCheck -ErrorAction Stop
                } else {
                    Write-Host "  Already up to date" -ForegroundColor Green
                }
            } else {
                # Fresh install - get the latest version
                $OnlineVersion = Find-Module -Name $Module -ErrorAction SilentlyContinue
                if ($OnlineVersion) {
                    Install-Module -Name $Module -RequiredVersion $OnlineVersion.Version -AllowClobber -Scope CurrentUser -SkipPublisherCheck -ErrorAction Stop
                } else {
                    Install-Module -Name $Module -AllowClobber -Scope CurrentUser -SkipPublisherCheck -ErrorAction Stop
                }
            }
            
            # Clean up old versions (keep only the latest)
            $AllVersions = Get-Module -Name $Module -ListAvailable | Sort-Object Version -Descending
            if ($AllVersions.Count -gt 1) {
                Write-Host "  Cleaning up old versions..." -ForegroundColor Gray
                for ($i = 1; $i -lt $AllVersions.Count; $i++) {
                    $OldVersion = $AllVersions[$i]
                    Write-Host "    Removing v$($OldVersion.Version)..." -ForegroundColor Gray
                    try {
                        Uninstall-Module -Name $Module -RequiredVersion $OldVersion.Version -Force -ErrorAction Stop
                    }
                    catch {
                        # Try manual removal if uninstall fails
                        Remove-Item -Path $OldVersion.ModuleBase -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            
            Write-Host "✅ $Module installed successfully" -ForegroundColor Green
        }
        catch {
            Write-Host "❌ Failed to install $Module`: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Create packages
if ($CreatePackages) {
    Write-Host "`nCreating Machine Configuration packages..." -ForegroundColor Yellow
    
    try {
        $PackageParams = @{
            ConfigurationLevel = 'All'
        }
        
        if ($UsePowerShell5) { $PackageParams.UsePowerShell5 = $true }
        if ($ForcePowerShell7) { $PackageParams.ForcePowerShell7 = $true }
        
        & .\scripts\New-ACSCMachineConfigurationPackage.ps1 @PackageParams
        Write-Host "✅ Packages created successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Failed to create packages: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Deploy to Azure if parameters provided
if ($SubscriptionId -and $ResourceGroupName -and $StorageAccountName) {
    Write-Host "`nDeploying to Azure..." -ForegroundColor Yellow
    
    try {
        $DeployParams = @{
            SubscriptionId = $SubscriptionId
            ResourceGroupName = $ResourceGroupName
            StorageAccountName = $StorageAccountName
            EnforcementMode = "ApplyAndAutoCorrect"
        }
        
        if ($TenantId) { $DeployParams.TenantId = $TenantId }
        if ($ServicePrincipalId) { $DeployParams.ServicePrincipalId = $ServicePrincipalId }
        if ($ServicePrincipalSecret) { $DeployParams.ServicePrincipalSecret = $ServicePrincipalSecret }
        
        & .\scripts\Deploy-ACSCToAzure.ps1 @DeployParams
        Write-Host "✅ Deployment completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Failed to deploy to Azure: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nNext steps:" -ForegroundColor Yellow

if (-not $InstallModules) {
    Write-Host "1. Install required modules:" -ForegroundColor Gray
    Write-Host "   .\setup.ps1 -InstallModules" -ForegroundColor White
}

if (-not $CreatePackages) {
    Write-Host "2. Create machine configuration packages:" -ForegroundColor Gray
    Write-Host "   .\setup.ps1 -CreatePackages" -ForegroundColor White
}

if (-not ($SubscriptionId -and $ResourceGroupName -and $StorageAccountName)) {
    Write-Host "3. Deploy to Azure:" -ForegroundColor Gray
    Write-Host "   .\setup.ps1 -SubscriptionId 'your-sub-id' -ResourceGroupName 'your-rg' -StorageAccountName 'yourstorageaccount'" -ForegroundColor White
}

Write-Host "4. Review documentation:" -ForegroundColor Gray
Write-Host "   - Implementation Guide: .\docs\implementation-guide.md" -ForegroundColor White
Write-Host "   - Configuration Reference: .\docs\configuration-reference.md" -ForegroundColor White

Write-Host "5. Monitor compliance in Azure Policy dashboard" -ForegroundColor Gray

Write-Host "`nFor help and support:" -ForegroundColor Yellow
Write-Host "- Check the README.md file" -ForegroundColor Gray
Write-Host "- Review ACSC documentation: https://www.cyber.gov.au/" -ForegroundColor Gray
Write-Host "- Azure Machine Configuration docs: https://learn.microsoft.com/en-us/azure/governance/machine-configuration/" -ForegroundColor Gray
