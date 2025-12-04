# ACSC Configuration Reference

This document provides detailed information about each ACSC Windows hardening configuration implemented in this project.

## High Priority Configurations

### User Account Control (UAC)

| Setting | Registry Key | Value | ACSC Recommendation |
|---------|--------------|-------|-------------------|
| Enable UAC | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA` | 1 | User Account Control: Run all administrators in Admin Approval Mode = Enabled |
| Admin Prompt Behavior | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | 1 | Prompt for credentials on the secure desktop |
| User Prompt Behavior | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser` | 0 | Automatically deny elevation requests |
| Built-in Admin Approval | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken` | 1 | Admin Approval Mode for Built-in Administrator = Enabled |

**Purpose**: Ensures all administrative actions require explicit approval and credentials are entered on the secure desktop.

### Attack Surface Reduction (ASR)

| Rule Name | GUID | Setting | Purpose |
|-----------|------|---------|---------|
| Block abuse of exploited vulnerable signed drivers | 56a863a9-875e-4185-98a7-b882c64b5ce5 | Block | Prevent malware from abusing legitimate but vulnerable drivers |
| Block Office applications from creating child processes | d4f940ab-401b-4efc-aadc-ad5f3c50688a | Block | Prevent Office macros from spawning malicious processes |
| Block credential stealing from LSASS | 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 | Block | Protect against credential dumping attacks |
| Block executable content from email | be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 | Block | Prevent execution of email attachments |
| Block JavaScript/VBScript from launching executables | d3e037e1-3eb8-44c8-a917-57927947596d | Block | Prevent script-based attacks |
| Use advanced protection against ransomware | c1db55ab-c21a-4637-bb3f-a12568109d35 | Block | Enhanced ransomware protection |

**Registry Location**: `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`

### Credential Protection

| Configuration | Registry Key | Value | Purpose |
|---------------|--------------|-------|---------|
| Disable WDigest | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` | 0 | Prevent plaintext password storage in memory |
| Enable VBS | `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity` | 1 | Enable Virtualization Based Security |
| Credential Guard | `HKLM\SYSTEM\CurrentControlSet\Control\LSA\LsaCfgFlags` | 1 | Enable Credential Guard with UEFI lock |

**Purpose**: Protects credentials in memory from theft and provides hardware-based isolation.

### Controlled Folder Access

| Setting | Registry Key | Value | Purpose |
|---------|--------------|-------|---------|
| Enable CFA | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\EnableControlledFolderAccess` | 1 | Protect important folders from ransomware |

**Purpose**: Prevents unauthorized applications from modifying files in protected folders.

### Early Launch Antimalware (ELAM)

| Setting | Registry Key | Value | Purpose |
|---------|--------------|-------|---------|
| Driver Load Policy | `HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy` | 3 | Allow good, unknown, and bad but critical drivers |

**Purpose**: Enables antimalware to start before other drivers during boot process.

### Exploit Protection

| Protection | Registry Key | Value | Purpose |
|------------|--------------|-------|---------|
| Disable DEP Override | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention` | 0 | Ensure DEP is enabled |
| Enable SEHOP | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\DisableExceptionChainValidation` | 0 | Structured Exception Handling Overwrite Protection |

**Purpose**: Provides system-wide exploit mitigation technologies.

### Local Administrator Password Solution (LAPS)

| Setting | Registry Key | Value | Purpose |
|---------|--------------|-------|---------|
| Enable LAPS | `HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\AdmPwdEnabled` | 1 | Enable LAPS functionality |
| Password Complexity | `HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordComplexity` | 4 | Large + small letters + numbers + specials |
| Password Length | `HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordLength` | 30 | 30 character passwords |
| Password Age | `HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordAgeDays` | 365 | Change every 365 days |

**Purpose**: Ensures unique, complex passwords for local administrator accounts.

## Medium Priority Configurations

### Account Lockout Policy

| Setting | Location | Value | Purpose |
|---------|----------|-------|---------|
| Account Lockout Threshold | Security Policy | 5 attempts | Prevent brute force attacks |
| Account Lockout Duration | Security Policy | 0 (manual unlock) | Require admin intervention |
| Reset Counter After | Security Policy | 15 minutes | Reset failed attempt counter |

### Anonymous Connections

| Setting | Registry Key | Value | Purpose |
|---------|--------------|-------|---------|
| Restrict Anonymous Access | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous` | 1 | Limit anonymous access to system information |
| Restrict Anonymous SAM | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM` | 1 | Prevent anonymous SAM enumeration |
| Disable Guest Logon | `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth` | 0 | Disable insecure guest authentication |

### Audit Event Management

| Setting | Registry Key | Value | Purpose |
|---------|--------------|-------|---------|
| Command Line Auditing | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled` | 1 | Log command line in process creation events |
| Security Log Size | `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize` | 2097152 | 2GB security log |
| System Log Size | `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize` | 65536 | 64MB system log |
| Application Log Size | `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\MaxSize` | 65536 | 64MB application log |

### BitLocker Drive Encryption

| Setting | Registry Key | Value | Purpose |
|---------|--------------|-------|---------|
| Enforce Encryption | `HKLM\SOFTWARE\Policies\Microsoft\FVE\UseAdvancedStartup` | 1 | Require advanced startup options |
| Require Startup PIN | `HKLM\SOFTWARE\Policies\Microsoft\FVE\UseTPMPIN` | 1 | Require PIN with TPM |
| Minimum PIN Length | `HKLM\SOFTWARE\Policies\Microsoft\FVE\MinimumPIN` | 14 | 14 character minimum PIN |

### Network Authentication

| Setting | Registry Key | Value | Purpose |
|---------|--------------|-------|---------|
| LM Authentication Level | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel` | 5 | Send NTLMv2 response only |
| NTLM Min Client Security | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec` | 536870912 | Require NTLMv2 and 128-bit encryption |
| NTLM Min Server Security | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec` | 536870912 | Require NTLMv2 and 128-bit encryption |

### Password Policy

| Setting | Location | Value | Purpose |
|---------|----------|-------|---------|
| Minimum Password Length | Security Policy | 15 characters | Strong password requirement |
| Maximum Password Age | Security Policy | 365 days | Regular password changes |
| Password Complexity | Security Policy | Enabled | Complex password requirements |
| Store Passwords Reversibly | Security Policy | Disabled | Prevent reversible encryption |

### PowerShell Security

| Setting | Registry Key | Value | Purpose |
|---------|--------------|-------|---------|
| Execution Policy | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy` | AllSigned | Only allow signed scripts |
| Script Block Logging | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging` | 1 | Log PowerShell script blocks |
| Transcription | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting` | 1 | Log all PowerShell activity |

### Remote Desktop Security

| Setting | Registry Key | Value | Purpose |
|---------|--------------|-------|---------|
| Security Layer | `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\SecurityLayer` | 2 | Use SSL security layer |
| User Authentication | `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication` | 1 | Require Network Level Authentication |
| Encryption Level | `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\MinEncryptionLevel` | 3 | High encryption level |
| Disable Clipboard | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableClip` | 1 | Disable clipboard redirection |
| Disable Drive Redirection | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm` | 1 | Disable drive redirection |

### SMB Security

| Setting | Registry Key | Value | Purpose |
|---------|--------------|-------|---------|
| Client Signing Required | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature` | 1 | Require SMB client signing |
| Server Signing Required | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature` | 1 | Require SMB server signing |
| Disable SMBv1 Client | `HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start` | 4 | Disable SMBv1 client |
| Disable SMBv1 Server | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1` | 0 | Disable SMBv1 server |

### Windows Firewall

| Setting | Registry Key | Value | Purpose |
|---------|--------------|-------|---------|
| Domain Profile | `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall` | 1 | Enable firewall for domain networks |
| Private Profile | `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall` | 1 | Enable firewall for private networks |
| Public Profile | `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall` | 1 | Enable firewall for public networks |

## Service Configurations

### Essential Services (Enabled)

| Service | Name | Startup Type | Purpose |
|---------|------|--------------|---------|
| Windows Defender | WinDefend | Automatic | Antimalware protection |
| Windows Firewall | MpsSvc | Automatic | Network protection |
| Security Center | wscsvc | Automatic | Security status monitoring |

### Disabled Services

| Service | Name | Startup Type | Purpose |
|---------|------|--------------|---------|
| Remote Registry | RemoteRegistry | Disabled | Prevent remote registry access |
| Telnet | TlntSvr | Disabled | Disable insecure remote access |

## Compliance Verification

### PowerShell Commands

```powershell
# Check UAC settings
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"

# Verify ASR rules
Get-MpPreference | Select-Object AttackSurfaceReductionRules_*

# Check Credential Guard status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

# Verify BitLocker status
Get-BitLockerVolume

# Check Windows Defender status
Get-MpComputerStatus

# Verify firewall status
Get-NetFirewallProfile
```

### Expected Values

All registry values should match the specified values in the configuration tables above. Services should be running or stopped as specified.

### Monitoring Queries

Use Azure Resource Graph to query compliance status:

```kusto
GuestConfigurationResources
| where name has "ACSC"
| summarize count() by complianceStatus
| render piechart
```

## Exceptions and Considerations

### Business Application Compatibility
- Some ASR rules may block legitimate business applications
- PowerShell execution policy may prevent legitimate scripts
- Remote Desktop restrictions may impact remote administration

### Performance Impact
- Credential Guard requires compatible hardware (TPM 2.0, UEFI, VBS)
- Real-time protection may impact system performance
- Audit logging increases storage requirements

### Operational Considerations
- LAPS requires Active Directory schema extension
- BitLocker recovery keys should be backed up to Active Directory
- Firewall rules may need customization for business applications
