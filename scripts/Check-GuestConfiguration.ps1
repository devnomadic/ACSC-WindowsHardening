# Check-GuestConfiguration.ps1
# Run this ON the Windows VM to check Guest Configuration status

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Guest Configuration Status Check" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# 1. Check Guest Configuration Service
Write-Host "`n1. Guest Configuration Service Status:" -ForegroundColor Yellow
$service = Get-Service -Name "GCService" -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "  Status: $($service.Status)" -ForegroundColor $(if ($service.Status -eq 'Running') { 'Green' } else { 'Red' })
    Write-Host "  Start Type: $($service.StartType)" -ForegroundColor Gray
} else {
    Write-Host "  Service not found" -ForegroundColor Red
}

# 2. Check Configuration Assignments
Write-Host "`n2. Configuration Assignments:" -ForegroundColor Yellow
$gcPath = "C:\ProgramData\GuestConfig\Configuration"
if (Test-Path $gcPath) {
    $configs = Get-ChildItem $gcPath -Directory
    Write-Host "  Found $($configs.Count) configuration(s):" -ForegroundColor Green
    $configs | ForEach-Object {
        Write-Host "    - $($_.Name)" -ForegroundColor Cyan
        Write-Host "      Last Modified: $($_.LastWriteTime)" -ForegroundColor Gray
    }
} else {
    Write-Host "  No configurations found" -ForegroundColor Red
}

# 3. Check ACSC Configurations
Write-Host "`n3. ACSC Configurations:" -ForegroundColor Yellow
$acscConfigs = @("ACSCHighPriorityHardening", "ACSCMediumPriorityHardening")
foreach ($configName in $acscConfigs) {
    $configPath = Join-Path $gcPath $configName
    if (Test-Path $configPath) {
        Write-Host "  ✓ $configName - FOUND" -ForegroundColor Green
        $files = Get-ChildItem $configPath -File -Recurse
        Write-Host "    Files: $($files.Count)" -ForegroundColor Gray
    } else {
        Write-Host "  ✗ $configName - NOT FOUND" -ForegroundColor Red
    }
}

# 4. Check Latest Logs
Write-Host "`n4. Latest Guest Configuration Logs:" -ForegroundColor Yellow
$logPath = "C:\ProgramData\GuestConfig\gc_agent_logs"
if (Test-Path $logPath) {
    $latestLog = Get-ChildItem $logPath -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latestLog) {
        Write-Host "  Latest log: $($latestLog.Name)" -ForegroundColor Cyan
        Write-Host "  Last modified: $($latestLog.LastWriteTime)" -ForegroundColor Gray
        Write-Host "`n  Last 30 lines:" -ForegroundColor Yellow
        Get-Content $latestLog.FullName -Tail 30 | ForEach-Object {
            $color = 'Gray'
            if ($_ -match '\[ERROR\]') { $color = 'Red' }
            elseif ($_ -match '\[WARNING\]') { $color = 'Yellow' }
            elseif ($_ -match 'ACSC') { $color = 'Cyan' }
            Write-Host "    $_" -ForegroundColor $color
        }
    }
} else {
    Write-Host "  Log directory not found" -ForegroundColor Red
}

# 5. Check Extension
Write-Host "`n5. Guest Configuration Extension:" -ForegroundColor Yellow
$extPath = "C:\Packages\Plugins\Microsoft.GuestConfiguration.ConfigurationforWindows"
if (Test-Path $extPath) {
    $versions = Get-ChildItem $extPath -Directory
    Write-Host "  Extension installed: YES" -ForegroundColor Green
    Write-Host "  Versions: $($versions.Name -join ', ')" -ForegroundColor Gray
} else {
    Write-Host "  Extension not found" -ForegroundColor Red
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Check Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
