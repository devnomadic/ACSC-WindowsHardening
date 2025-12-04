# Verify GitHub Release Package Hashes
# This script downloads packages from the latest GitHub release and verifies their SHA256 hashes

param(
    [Parameter(Mandatory = $false)]
    [string]$Repository = "devnomadic/ACSC-WindowsHardening",
    
    [Parameter(Mandatory = $false)]
    [string]$ReleaseVersion  # If not specified, uses latest release
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "GitHub Release Hash Verification" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

try {
    # Get release information
    if ($ReleaseVersion) {
        $ReleaseUrl = "https://api.github.com/repos/$Repository/releases/tags/$ReleaseVersion"
        Write-Host "`nFetching release: $ReleaseVersion" -ForegroundColor Yellow
    } else {
        $ReleaseUrl = "https://api.github.com/repos/$Repository/releases/latest"
        Write-Host "`nFetching latest release..." -ForegroundColor Yellow
    }
    
    $Release = Invoke-RestMethod -Uri $ReleaseUrl -Headers @{
        "Accept" = "application/vnd.github+json"
        "User-Agent" = "PowerShell-Hash-Verification"
    }
    
    Write-Host "Release: $($Release.tag_name) - $($Release.name)" -ForegroundColor Green
    Write-Host "Published: $($Release.published_at)" -ForegroundColor Gray
    Write-Host "Author: $($Release.author.login)" -ForegroundColor Gray
    
    # Find all package files and their corresponding hash files
    $PackageAssets = $Release.assets | Where-Object { $_.name -like "*.zip" -and $_.name -notlike "*.sha256" }
    
    if ($PackageAssets.Count -eq 0) {
        Write-Warning "No package files found in this release!"
        exit 1
    }
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Verifying Package Integrity" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    $AllValid = $true
    $Results = @()
    
    foreach ($PackageAsset in $PackageAssets) {
        $PackageName = $PackageAsset.name
        $HashAssetName = "$PackageName.sha256"
        $HashAsset = $Release.assets | Where-Object { $_.name -eq $HashAssetName }
        
        Write-Host "`n--- $PackageName ---" -ForegroundColor Yellow
        
        if (-not $HashAsset) {
            Write-Host "❌ Hash file not found: $HashAssetName" -ForegroundColor Red
            $AllValid = $false
            $Results += @{
                Package = $PackageName
                Status = "MISSING_HASH"
                Valid = $false
            }
            continue
        }
        
        try {
            # Download hash file content
            Write-Host "Downloading hash file..." -ForegroundColor Gray
            $HashResponse = Invoke-WebRequest -Uri $HashAsset.browser_download_url
            $HashContent = [System.Text.Encoding]::UTF8.GetString($HashResponse.Content)
            $ExpectedHash = $HashContent.Trim().Split()[0].ToUpper()
            
            Write-Host "Expected hash: $ExpectedHash" -ForegroundColor Cyan
            
            # Download package to temp location
            Write-Host "Downloading package..." -ForegroundColor Gray
            $TempDir = if ($env:TEMP) { $env:TEMP } elseif ($env:TMPDIR) { $env:TMPDIR } else { "/tmp" }
            $TempFile = Join-Path $TempDir $PackageName
            Invoke-WebRequest -Uri $PackageAsset.browser_download_url -OutFile $TempFile
            
            # Calculate actual hash
            Write-Host "Calculating hash..." -ForegroundColor Gray
            $ActualHash = (Get-FileHash -Path $TempFile -Algorithm SHA256).Hash.ToUpper()
            
            Write-Host "Actual hash:   $ActualHash" -ForegroundColor Cyan
            
            # Compare hashes
            if ($ExpectedHash -eq $ActualHash) {
                Write-Host "✅ VERIFIED - Hash matches!" -ForegroundColor Green
                $Results += @{
                    Package = $PackageName
                    Status = "VERIFIED"
                    Valid = $true
                    ExpectedHash = $ExpectedHash
                    ActualHash = $ActualHash
                }
            } else {
                Write-Host "❌ MISMATCH - Hashes do not match!" -ForegroundColor Red
                $AllValid = $false
                $Results += @{
                    Package = $PackageName
                    Status = "MISMATCH"
                    Valid = $false
                    ExpectedHash = $ExpectedHash
                    ActualHash = $ActualHash
                }
            }
            
            # Cleanup temp file
            Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "❌ ERROR: $($_.Exception.Message)" -ForegroundColor Red
            $AllValid = $false
            $Results += @{
                Package = $PackageName
                Status = "ERROR"
                Valid = $false
                Error = $_.Exception.Message
            }
        }
    }
    
    # Display summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Verification Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    foreach ($Result in $Results) {
        $StatusColor = if ($Result.Valid) { "Green" } else { "Red" }
        $StatusIcon = if ($Result.Valid) { "✅" } else { "❌" }
        
        Write-Host "`n$StatusIcon $($Result.Package)" -ForegroundColor $StatusColor
        Write-Host "   Status: $($Result.Status)" -ForegroundColor Gray
        
        if ($Result.ExpectedHash) {
            Write-Host "   Expected: $($Result.ExpectedHash)" -ForegroundColor Gray
            Write-Host "   Actual:   $($Result.ActualHash)" -ForegroundColor Gray
        }
        
        if ($Result.Error) {
            Write-Host "   Error: $($Result.Error)" -ForegroundColor Red
        }
    }
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    
    if ($AllValid) {
        Write-Host "✅ All packages verified successfully!" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "❌ Some packages failed verification!" -ForegroundColor Red
        exit 1
    }
}
catch {
    Write-Error "Failed to verify release: $($_.Exception.Message)"
    exit 1
}
