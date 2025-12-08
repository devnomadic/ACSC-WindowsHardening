# Create Machine Configuration Package for ACSC Windows Hardening
# This script creates Azure Machine Configuration packages from the DSC configurations

param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "./packages",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("HighPriority", "MediumPriority", "All")]
    [string]$ConfigurationLevel = "All",
    
    [Parameter(Mandatory = $false)]
    [switch]$UsePowerShell5,
    
    [Parameter(Mandatory = $false)]
    [switch]$ForcePowerShell7
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ACSC Machine Configuration Package Creation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Ensure PSDesiredStateConfiguration is installed
Write-Host "`nChecking PSDesiredStateConfiguration module..." -ForegroundColor Yellow
$PSDsc = Get-Module -Name PSDesiredStateConfiguration -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1

if (-not $PSDsc) {
    Write-Host "PSDesiredStateConfiguration not found. Installing..." -ForegroundColor Yellow
    Install-Module -Name PSDesiredStateConfiguration -Force -AllowClobber -Scope CurrentUser -SkipPublisherCheck
    $PSDsc = Get-Module -Name PSDesiredStateConfiguration -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    Write-Host "  ✅ PSDesiredStateConfiguration $($PSDsc.Version) installed" -ForegroundColor Green
} else {
    Write-Host "  ✅ PSDesiredStateConfiguration $($PSDsc.Version) is installed" -ForegroundColor Green
}

# Force import latest PSDesiredStateConfiguration for PowerShell 7+ compatibility
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $LatestPSDsc = Get-Module -Name PSDesiredStateConfiguration -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    if ($LatestPSDsc) {
        Import-Module -Name PSDesiredStateConfiguration -RequiredVersion $LatestPSDsc.Version -Force
        Write-Host "  ✅ Loaded PSDesiredStateConfiguration $($LatestPSDsc.Version)" -ForegroundColor Green
    }
}

# Import required modules
$RequiredModules = @(
    'GuestConfiguration',
    'Az.Accounts',
    'Az.Resources',
    'Az.Storage'
)

foreach ($Module in $RequiredModules) {
    if (-not (Get-Module -Name $Module -ListAvailable)) {
        Write-Host "Installing module: $Module" -ForegroundColor Yellow
        Install-Module -Name $Module -Force -AllowClobber -Scope CurrentUser
    }
    Import-Module -Name $Module -Force
}

# Clean up multiple versions of DSC resource modules
Write-Host "`nChecking for multiple module versions..." -ForegroundColor Yellow

# Define required module versions
$DscModules = @{
    'SecurityPolicyDsc' = $null  # Use latest available
    'AuditPolicyDsc'    = $null  # Use latest
    'PSDscResources'    = $null  # Use latest
    'cChoco'            = $null  # Use latest
    'xPSDesiredStateConfiguration' = $null  # Use latest
}

foreach ($ModuleName in $DscModules.Keys) {
    $RequiredVersion = $DscModules[$ModuleName]
    $AllVersions = Get-Module -Name $ModuleName -ListAvailable | Sort-Object Version -Descending
    
    if ($AllVersions.Count -eq 0) {
        Write-Host "$ModuleName not found. Installing..." -ForegroundColor Yellow
        if ($RequiredVersion) {
            Install-Module -Name $ModuleName -RequiredVersion $RequiredVersion -Force -AllowClobber -Scope CurrentUser -SkipPublisherCheck
            Write-Host "  ✅ $ModuleName version $RequiredVersion installed" -ForegroundColor Green
        }
        else {
            Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser -SkipPublisherCheck
            Write-Host "  ✅ $ModuleName installed" -ForegroundColor Green
        }
    }
    elseif ($AllVersions.Count -gt 1 -or ($RequiredVersion -and $AllVersions[0].Version -ne $RequiredVersion)) {
        Write-Host "Found multiple versions or wrong version of $ModuleName. Cleaning up..." -ForegroundColor Yellow
        
        # Remove ALL versions
        foreach ($Version in $AllVersions) {
            Write-Host "  Removing: $ModuleName version $($Version.Version)..." -ForegroundColor Gray
            try {
                Uninstall-Module -Name $ModuleName -RequiredVersion $Version.Version -Force -ErrorAction Stop
                Write-Host "    ✅ Removed successfully" -ForegroundColor Green
            }
            catch {
                Write-Host "    ⚠️  Could not uninstall: $($_.Exception.Message)" -ForegroundColor Yellow
                Write-Host "    Attempting manual removal..." -ForegroundColor Yellow
                Remove-Item -Path $Version.ModuleBase -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Install correct version
        if ($RequiredVersion) {
            Install-Module -Name $ModuleName -RequiredVersion $RequiredVersion -Force -AllowClobber -Scope CurrentUser -SkipPublisherCheck
            Write-Host "  ✅ $ModuleName version $RequiredVersion installed" -ForegroundColor Green
        }
        else {
            Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser -SkipPublisherCheck
            Write-Host "  ✅ $ModuleName latest version installed" -ForegroundColor Green
        }
    }
    else {
        Write-Host "$ModuleName version $($AllVersions[0].Version) is installed" -ForegroundColor Green
    }
}

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force
}

# Determine which PowerShell to use for DSC compilation
$UseWindowsPowerShell = $false

if ($ForcePowerShell7) {
    Write-Host "`n⚙️  PowerShell 7 forced for DSC compilation" -ForegroundColor Cyan
    $UseWindowsPowerShell = $false
}
elseif ($UsePowerShell5) {
    Write-Host "`n⚙️  PowerShell 5.1 (Windows PowerShell) forced for DSC compilation" -ForegroundColor Cyan
    $UseWindowsPowerShell = $true
}
else {
    # Default behavior: Use PS5.1 if running in PS7+
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        Write-Host "`n⚙️  PowerShell 7+ detected - will use Windows PowerShell 5.1 for DSC compilation (default)" -ForegroundColor Cyan
        $UseWindowsPowerShell = $true
    }
    else {
        Write-Host "`n⚙️  Windows PowerShell 5.1 detected - will compile DSC directly" -ForegroundColor Cyan
        $UseWindowsPowerShell = $false
    }
}

function New-ACSCMachineConfigurationPackage {
    param(
        [string]$ConfigurationName,
        [string]$ConfigurationPath,
        [string]$OutputPath,
        [string]$Description
    )
    
    Write-Host "Creating Machine Configuration Package: $ConfigurationName" -ForegroundColor Green
    
    try {
        # Clean up any loaded DSC resource modules to avoid version conflicts
        Write-Host "Cleaning up module environment..." -ForegroundColor Yellow
        
        # Remove ALL DSC-related modules from memory
        $DscModules = @('PSDesiredStateConfiguration', 'SecurityPolicyDsc', 'AuditPolicyDsc', 'PSDscResources', 'cChoco', 'xPSDesiredStateConfiguration')
        foreach ($ModuleName in $DscModules) {
            Get-Module -Name $ModuleName | Remove-Module -Force -ErrorAction SilentlyContinue
        }
        
        # Clear the DSC resource cache
        if (Test-Path "$env:LOCALAPPDATA\Microsoft\Windows\PowerShell\Configuration\BuiltinProvCache") {
            Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\PowerShell\Configuration\BuiltinProvCache" -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # Remove any existing compiled MOF files
        Write-Host "Removing old compiled configurations..." -ForegroundColor Yellow
        $MofPath = Join-Path (Split-Path $ConfigurationPath) $ConfigurationName
        if (Test-Path $MofPath) {
            Remove-Item $MofPath -Recurse -Force
        }
        
        # Force PowerShell to start fresh with DSC compilation
        Write-Host "Compiling DSC configuration with latest module versions..." -ForegroundColor Yellow
        
        # Convert to absolute paths
        $AbsoluteConfigPath = Resolve-Path $ConfigurationPath -ErrorAction Stop
        $ConfigDir = Split-Path $AbsoluteConfigPath -Parent
        
        # Create MOF output directory with absolute path
        $AbsoluteMofPath = Join-Path (Get-Location).Path $MofPath
        if (-not (Test-Path $AbsoluteMofPath)) {
            New-Item -Path $AbsoluteMofPath -ItemType Directory -Force | Out-Null
        }
        
        # Execute the configuration script in a clean session to avoid module conflicts
        # Use PowerShell 5.1 (Windows PowerShell) for DSC compilation
        # Read the script content and invoke it directly to bypass execution policy
        $scriptContent = Get-Content -Path $AbsoluteConfigPath -Raw
        
        # Remove the automatic MOF generation line at the end of the script
        # We'll invoke the configuration function manually with the correct output path
        $scriptContent = $scriptContent -replace '# Generate the MOF file[\s\S]*$', ''
        
        # Get module paths to pass to spawned PowerShell session
        $modulePaths = $env:PSModulePath
        
        if ($UseWindowsPowerShell) {
            # Launch Windows PowerShell 5.1 for DSC compilation
            Write-Host "Launching Windows PowerShell 5.1 for DSC compilation..." -ForegroundColor Yellow
            
            # Build PSModulePath that includes DSC resource modules but excludes incompatible PSDesiredStateConfiguration v2.0.7
            $ps5ModulePaths = @()
            
            # Add Windows PowerShell paths first (includes PSDesiredStateConfiguration v1.1)
            $ps5ModulePaths += "$env:ProgramFiles\WindowsPowerShell\Modules"
            $ps5ModulePaths += "$env:SystemRoot\system32\WindowsPowerShell\v1.0\Modules"
            
            # Add Windows PowerShell user modules
            $userModulePath = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Modules'
            if (Test-Path $userModulePath) {
                $ps5ModulePaths += $userModulePath
            }
            
            # Add PowerShell 7 user modules path (contains DSC resource modules)
            # but we'll exclude PSDesiredStateConfiguration from import
            $ps7UserModulePath = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'PowerShell\Modules'
            if (Test-Path $ps7UserModulePath) {
                $ps5ModulePaths += $ps7UserModulePath
            }
            
            $ps5ModulePathString = $ps5ModulePaths -join ';'
            
            # Write script to temp file to avoid command line length/escaping issues
            $tempScript = [System.IO.Path]::GetTempFileName() + ".ps1"
            $compileScript = @"
# Set PSModulePath to include all necessary module locations
`$env:PSModulePath = '$ps5ModulePathString'

# Import PSDesiredStateConfiguration v1.1 from Windows PowerShell (built-in)
# This prevents trying to load incompatible v2.0.7 from PowerShell 7 modules
`$psDscPath = "$env:SystemRoot\system32\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration"
if (Test-Path `$psDscPath) {
    Import-Module `$psDscPath -Force -WarningAction SilentlyContinue
}

`$scriptContent = @'
$scriptContent
'@
Invoke-Expression `$scriptContent
$ConfigurationName -OutputPath '$AbsoluteMofPath'
"@
            Set-Content -Path $tempScript -Value $compileScript -Encoding UTF8
            
            try {
                # Execute the temp script file
                $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $tempScript 2>&1
                Write-Host ($output | Out-String)
                
                if ($LASTEXITCODE -ne 0) {
                    throw "DSC compilation failed in Windows PowerShell 5.1 (Exit code: $LASTEXITCODE)"
                }
            }
            finally {
                Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
            }
        }
        else {
            # Compile DSC in current PowerShell session (PS7 or PS5.1)
            Write-Host "Compiling DSC configuration in current PowerShell session..." -ForegroundColor Yellow
            Invoke-Expression $scriptContent
            & $ConfigurationName -OutputPath $AbsoluteMofPath
        }
        
        # Verify MOF was created
        $MofFile = Join-Path $AbsoluteMofPath "localhost.mof"
        if (-not (Test-Path $MofFile)) {
            throw "MOF file was not created at expected path: $MofFile"
        }
        
        Write-Host "MOF file created: $MofFile" -ForegroundColor Green
        
        # Create the package
        $PackagePath = Join-Path $OutputPath "$ConfigurationName.zip"
        
        if (Test-Path $PackagePath) {
            Remove-Item $PackagePath -Force
        }
        
        $Package = New-GuestConfigurationPackage -Name $ConfigurationName `
                                               -Configuration (Join-Path $AbsoluteMofPath "localhost.mof") `
                                               -Path $OutputPath `
                                               -Type AuditAndSet `
                                               -Force
        
        Write-Host "Package created successfully: $($Package.Path)" -ForegroundColor Green
        return $Package
    }
    catch {
        Write-Error "Failed to create package for $ConfigurationName`: $($_.Exception.Message)"
        return $null
    }
}

# Create packages based on configuration level
switch ($ConfigurationLevel) {
    "HighPriority" {
        Write-Host "Creating High Priority ACSC Configuration Package..." -ForegroundColor Cyan
        
        $HighPriorityPackage = New-ACSCMachineConfigurationPackage `
            -ConfigurationName "ACSCHighPriorityHardening" `
            -ConfigurationPath "./configurations/high-priority/ACSCHighPriorityHardening.ps1" `
            -OutputPath $OutputPath `
            -Description "ACSC High Priority Windows Hardening Configuration"
    }
    
    "MediumPriority" {
        Write-Host "Creating Medium Priority ACSC Configuration Package..." -ForegroundColor Cyan
        
        $MediumPriorityPackage = New-ACSCMachineConfigurationPackage `
            -ConfigurationName "ACSCMediumPriorityHardening" `
            -ConfigurationPath "./configurations/medium-priority/ACSCMediumPriorityHardening.ps1" `
            -OutputPath $OutputPath `
            -Description "ACSC Medium Priority Windows Hardening Configuration"
    }
    
    "All" {
        Write-Host "Creating All ACSC Configuration Packages..." -ForegroundColor Cyan
        
        $HighPriorityPackage = New-ACSCMachineConfigurationPackage `
            -ConfigurationName "ACSCHighPriorityHardening" `
            -ConfigurationPath "./configurations/high-priority/ACSCHighPriorityHardening.ps1" `
            -OutputPath $OutputPath `
            -Description "ACSC High Priority Windows Hardening Configuration"
        
        $MediumPriorityPackage = New-ACSCMachineConfigurationPackage `
            -ConfigurationName "ACSCMediumPriorityHardening" `
            -ConfigurationPath "./configurations/medium-priority/ACSCMediumPriorityHardening.ps1" `
            -OutputPath $OutputPath `
            -Description "ACSC Medium Priority Windows Hardening Configuration"
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Package Creation Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$PackageFiles = Get-ChildItem -Path $OutputPath -Filter "*.zip"
foreach ($Package in $PackageFiles) {
    Write-Host "Package: $($Package.Name)" -ForegroundColor Green
    Write-Host "Size: $([math]::Round($Package.Length / 1KB, 2)) KB" -ForegroundColor Gray
    Write-Host "Path: $($Package.FullName)" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Upload packages to Azure Storage Account" -ForegroundColor Gray
Write-Host "2. Create Azure Policy definitions" -ForegroundColor Gray
Write-Host "3. Assign policies to target scopes" -ForegroundColor Gray
Write-Host "4. Monitor compliance through Azure Policy dashboard" -ForegroundColor Gray
