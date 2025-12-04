# Native Windows Support Analysis

## Summary
All configurations in this project use only **native Windows features** that are available in standard Windows installations. No third-party software or additional agents are required.

## Windows SKU Requirements

### High-Priority Configuration

#### Features Available in All Windows 10/11 SKUs
- **Windows Defender Antivirus**: Native to all Windows 10/11 SKUs (Home, Pro, Enterprise, Education)
- **Windows Firewall**: Native to all Windows 10/11 SKUs
- **Security Center**: Native to all Windows 10/11 SKUs
- **Registry-based Group Policy Preferences**: Available in all SKUs
- **Audit Policy**: Native to all Windows 10/11 SKUs
- **User Rights Assignment**: Native to all Windows 10/11 SKUs
- **Security Options**: Native to all Windows 10/11 SKUs
- **PowerShell**: Native to all Windows 10/11 SKUs
- **Data Execution Prevention (DEP)**: Native to all Windows 10/11 SKUs
- **SEHOP**: Native to all Windows 10/11 SKUs

#### Features Requiring Pro/Enterprise/Education SKUs
- **Attack Surface Reduction (ASR) Rules**: Available in Windows 10/11 Pro, Enterprise, Education with Microsoft Defender Antivirus
- **Credential Guard**: Requires Windows 10/11 Enterprise or Education
- **Device Guard/HVCI**: Requires Windows 10/11 Enterprise or Education
- **Controlled Folder Access**: Available in Windows 10/11 Pro, Enterprise, Education
- **Early Launch Antimalware (ELAM)**: Available in all SKUs but enhanced features in Pro+

### Medium-Priority Configuration

#### Features Available in All Windows 10/11 SKUs
- **All DSC Resources Used**: PSDscResources, SecurityPolicyDsc, AuditPolicyDsc, ComputerManagementDsc are Microsoft-provided
- **Registry-based Group Policy Preferences**: Available in all SKUs
- **Windows Features Management**: Native to all SKUs
- **Service Management**: Native to all SKUs
- **PowerShell Logging**: Native to all SKUs
- **Windows Update Policies**: Native to all SKUs
- **Remote Desktop Policies**: Native to all SKUs

#### Features Requiring Pro/Enterprise/Education SKUs
- **BitLocker Drive Encryption**: Available in Windows 10/11 Pro, Enterprise, Education (not in Home)
- **Group Policy Management**: Enhanced in Pro+ editions
- **Advanced Audit Policies**: Enhanced features in Pro+ editions

## Hardware Requirements

### Credential Guard and Device Guard
- **UEFI Firmware**: Required
- **Secure Boot**: Required
- **TPM 2.0**: Required for full functionality
- **Virtualization Extensions**: Required (Intel VT-x or AMD-V)
- **Second Level Address Translation (SLAT)**: Required
- **IOMMU**: Required (Intel VT-d or AMD-Vi)

### BitLocker
- **TPM 1.2 or 2.0**: Recommended (can use USB key or password as alternative)
- **UEFI Firmware**: Required for secure boot integration

## Dependencies

### Required: Windows Security Baseline Templates
- ✅ **Windows Security Baseline installation required**: Provides extended Group Policy templates
- ✅ **SecurityPolicyDsc module dependency**: Requires baseline policy definitions
- ✅ **AuditPolicyDsc module dependency**: Requires extended audit policy categories

### Confirmed: No Third-Party Requirements
- ❌ **No LAPS dependency**: Local Administrator Password Solution not required
- ❌ **No additional antivirus**: Uses native Windows Defender
- ❌ **No domain controller requirements**: All settings work on standalone workstations
- ❌ **No additional agents**: Pure DSC and native Windows features

### DSC Module Dependencies
All DSC modules used are Microsoft-provided and available through PowerShell Gallery:
- `PSDscResources`: Microsoft official DSC resources
- `SecurityPolicyDsc`: Microsoft community DSC resources for security policies
- `AuditPolicyDsc`: Microsoft community DSC resources for audit policies
- `ComputerManagementDsc`: Microsoft community DSC resources for computer management

## Compatibility Matrix

| Feature | Home | Pro | Enterprise | Education | Notes |
|---------|------|-----|------------|-----------|-------|
| Basic Security Policies | ✅ | ✅ | ✅ | ✅ | All DSC resources work |
| Windows Defender | ✅ | ✅ | ✅ | ✅ | Full feature set in Pro+ |
| ASR Rules | ❌ | ✅ | ✅ | ✅ | Pro+ only |
| Credential Guard | ❌ | ❌ | ✅ | ✅ | Enterprise/Education only |
| Device Guard/HVCI | ❌ | ❌ | ✅ | ✅ | Enterprise/Education only |
| BitLocker | ❌ | ✅ | ✅ | ✅ | Pro+ only |
| Controlled Folder Access | ❌ | ✅ | ✅ | ✅ | Pro+ only |
| Group Policy Preferences | ✅ | ✅ | ✅ | ✅ | Registry-based, works on all |

## Recommended Target Environments

### Primary Target: Windows 10/11 Pro, Enterprise, Education
- Full feature compatibility
- All ACSC recommendations can be implemented
- Hardware security features available

### Secondary Target: Windows 10/11 Home
- Most security policies work
- Some advanced features (ASR, Credential Guard, BitLocker) unavailable
- Still provides significant security hardening

## Validation Commands

To verify feature availability on a target system:

```powershell
# Check Windows SKU
Get-ComputerInfo | Select-Object WindowsProductName, WindowsEditionId

# Check TPM availability
Get-Tpm

# Check virtualization support
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V

# Check Credential Guard eligibility
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

# Check BitLocker support
Get-BitLockerVolume
```

## Conclusion

This ACSC Windows Hardening implementation is designed to be **native-first** and **dependency-free**. All configurations use only built-in Windows features and Microsoft-provided DSC resources. The solution automatically adapts to different Windows SKUs by configuring only the features available in each edition.
