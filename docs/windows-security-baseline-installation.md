# Windows Security Baseline Installation Guide

## Overview

Our ACSC Windows Hardening implementation **requires** the Windows Security Baseline to be installed because many of the DSC resources we use depend on **extended Group Policy templates** that are not available in vanilla Windows.

## What is Required

### Windows Security Baseline (Security Compliance Toolkit)
The Security Compliance Toolkit provides:
- **Extended Group Policy templates** (.admx/.adml files)
- **Additional security policy categories** used by SecurityPolicyDsc
- **Enhanced audit policy subcategories** required by AuditPolicyDsc
- **Modern security options** that vanilla Windows doesn't expose

## Installation Steps

### 1. Download Security Compliance Toolkit

```powershell
# Download from Microsoft
$downloadUrl = "https://www.microsoft.com/download/details.aspx?id=55319"
Start-Process $downloadUrl
```

### 2. Extract and Install Policy Templates

After downloading the Security Compliance Toolkit:

1. **Extract the toolkit** to a temporary directory
2. **Locate the policy templates** in the toolkit:
   - `GP Templates\DomainSysvol\PolicyDefinitions\*.admx`
   - `GP Templates\DomainSysvol\PolicyDefinitions\en-US\*.adml`

3. **Copy templates to system location**:
   ```powershell
   # Run as Administrator
   $PolicyPath = "$env:SystemRoot\PolicyDefinitions"
   $LanguagePath = "$PolicyPath\en-US"
   
   # Copy .admx files
   Copy-Item ".\GP Templates\DomainSysvol\PolicyDefinitions\*.admx" -Destination $PolicyPath -Force
   
   # Copy .adml files
   Copy-Item ".\GP Templates\DomainSysvol\PolicyDefinitions\en-US\*.adml" -Destination $LanguagePath -Force
   ```

### 3. Verify Installation

```powershell
# Check for key templates
$PolicyPath = "$env:SystemRoot\PolicyDefinitions"
$RequiredTemplates = @(
    'MSS-legacy.admx',
    'MSSecurityGuide.admx',
    'WindowsDefender.admx'
)

foreach ($Template in $RequiredTemplates) {
    $TemplatePath = Join-Path $PolicyPath $Template
    if (Test-Path $TemplatePath) {
        Write-Host "✅ Found: $Template" -ForegroundColor Green
    } else {
        Write-Host "❌ Missing: $Template" -ForegroundColor Red
    }
}
```

## Alternative: Domain Environment

If you're in a **domain environment**, you can also:

1. **Copy templates to SYSVOL**:
   ```
   \\domain.com\SYSVOL\domain.com\Policies\PolicyDefinitions\
   ```

2. **Use Group Policy Management Console** to verify templates are available

## Why This is Required

### DSC Resource Dependencies

Our configurations use these DSC resources that require extended policy templates:

| DSC Resource | Requires Baseline Templates | Reason |
|--------------|----------------------------|---------|
| **SecurityPolicyDsc** | ✅ Yes | Extended security options not in vanilla Windows |
| **AuditPolicyDsc** | ✅ Yes | Advanced audit subcategories |
| **AccountPolicy** | ❌ No | Basic account policies are native |
| **UserRightsAssignment** | ❌ No | User rights are native |

### Specific Examples

Without the baseline templates, these configurations would **fail**:

```powershell
# This requires extended templates
SecurityOption 'NetworkSecurityLanManagerAuthLevel' {
    Name = 'Network_security_LAN_Manager_authentication_level'
    Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
}

# This requires advanced audit categories
AuditPolicySubcategory 'AuditAccountLogon' {
    Name      = 'Credential Validation'
    AuditFlag = 'Success and Failure'
    Ensure    = 'Present'
}
```

## Automated Installation Script

We've included automated checks in our setup script:

```powershell
# Run the setup script - it will check for baseline templates
.\setup.ps1 -InstallModules
```

The script will:
- ✅ **Check** for baseline template installation
- ⚠️ **Warn** if templates are missing
- 🔗 **Provide** download links and instructions

## Troubleshooting

### Templates Not Found After Installation

1. **Verify extraction location**:
   ```powershell
   Get-ChildItem "$env:SystemRoot\PolicyDefinitions\*.admx" | Select-String "MSS|MSSecurityGuide"
   ```

2. **Check permissions**:
   - Ensure you're running as Administrator
   - Verify NTFS permissions on PolicyDefinitions folder

3. **Restart required services**:
   ```powershell
   Restart-Service gpsvc -Force
   ```

### DSC Compilation Errors

If you see errors like:
```
Cannot find policy <PolicyName>
```

This typically means:
- ❌ **Baseline templates not installed**
- ❌ **Wrong language pack** (ensure en-US .adml files are present)
- ❌ **Group Policy service** needs restart

## Verification Commands

After installation, verify everything works:

```powershell
# Test DSC compilation
Configuration Test {
    Import-DscResource -ModuleName SecurityPolicyDsc
    
    Node localhost {
        SecurityOption 'TestPolicy' {
            Name = 'Network_security_LAN_Manager_authentication_level'
            Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
        }
    }
}

# Compile test configuration
Test -OutputPath ".\Test"
```

If compilation succeeds without errors, the baseline templates are properly installed.

## Summary

The **Windows Security Baseline is a mandatory dependency** for our ACSC implementation because:

1. **Extended policy templates** are required by DSC resources
2. **Modern security options** aren't available in vanilla Windows
3. **Advanced audit categories** need additional definitions
4. **Best practice implementation** leverages Microsoft's enhanced policy framework

Install the Security Compliance Toolkit and extract the policy templates **before** attempting to deploy our ACSC configurations.
