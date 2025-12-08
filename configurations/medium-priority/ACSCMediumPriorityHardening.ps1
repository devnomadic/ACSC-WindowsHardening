Configuration ACSCMediumPriorityHardening {
    param(
        [Parameter()]
        [string[]]$ComputerName = 'localhost'
    )

    Import-DscResource -ModuleName 'PSDscResources'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'
    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'cChoco'
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    Node $ComputerName {
        
        # ================================
        # ACSC Medium Priority: Prerequisites
        # ================================
        
        # Ensure Chocolatey is installed
        cChocoInstaller 'InstallChocolatey' {
            InstallDir = 'C:\ProgramData\chocolatey'
        }
        
        # Install Windows Security Baseline package
        cChocoPackageInstaller 'InstallWinSecurityBaseline' {
            Name = 'winsecuritybaseline'
            Ensure = 'Present'
            AutoUpgrade = $false
            DependsOn = '[cChocoInstaller]InstallChocolatey'
        }
        
        # ================================
        # ACSC Medium Priority: Account Policies (September 2025 Update)
        # ================================
        AccountPolicy 'AccountSecurityPolicy' {
            Name = 'AccountSecurityPolicy'
            # Account Lockout Policy (ACSC: locked until admin unlocks)
            Account_lockout_duration = 0  # 0 = must be unlocked by administrator
            Account_lockout_threshold = 5
            Reset_account_lockout_counter_after = 0  # Must be 0 when duration is 0 (Windows constraint)
            # Password Policy
            # Note: Length over complexity - 14 char passwords (DSC max) are stronger than 8 char complex
            Minimum_Password_Age = 1
            Maximum_Password_Age = 0  # 0 = passwords never expire (September 2025 change)
            Minimum_Password_Length = 14  # Maximum supported by AccountPolicy DSC resource
            Password_must_meet_complexity_requirements = 'Disabled'  # Disabled in favor of length (September 2025 change)
            Enforce_password_history = 24
            Store_passwords_using_reversible_encryption = 'Disabled'
        }

        # Machine account lockout threshold (September 2025 addition)
        # Note: This is configured via Interactive_logon_Machine_account_lockout_threshold
        SecurityOption 'MachineAccountLockoutThreshold' {
            Name = 'Interactive_logon_Machine_account_lockout_threshold'
            Interactive_logon_Machine_account_lockout_threshold = 5
        }

        # Legacy registry setting for Remote Access (no DSC equivalent)
        Registry 'AccountLockoutThresholdRemoteAccess' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout'
            ValueName   = 'MaxDenials'
            ValueType   = 'DWord'
            ValueData   = '5'
            Force       = $true
        }

        # Modern password policy registry settings (Group Policy preferences)
        Registry 'DisablePicturePassword' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName   = 'BlockDomainPicturePassword'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'DisablePINLogon' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName   = 'AllowDomainPINLogon'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }

        # ================================
        # ACSC Medium Priority: Security Options
        # ================================
        SecurityOption 'InteractiveLogonMessageTitle' {
            Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
            Interactive_logon_Message_title_for_users_attempting_to_log_on = 'WARNING'
        }

        SecurityOption 'InteractiveLogonMessageText' {
            Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
            Interactive_logon_Message_text_for_users_attempting_to_log_on = 'This system is for authorized users only. All activities are monitored and logged.'
        }

        SecurityOption 'NetworkSecurityLanManagerAuthLevel' {
            Name = 'Network_security_LAN_Manager_authentication_level'
            Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
        }

        SecurityOption 'NetworkSecurityNTLMMinClientSec' {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
        }

        SecurityOption 'NetworkSecurityNTLMMinServerSec' {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
        }

        SecurityOption 'RestrictAnonymousEnumSAM' {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
        }

        SecurityOption 'RestrictAnonymousEnumSAMAndShares' {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
        }

        SecurityOption 'RequireClientSigning' {
            Name = 'Microsoft_network_client_Digitally_sign_communications_always'
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
        }

        SecurityOption 'RequireServerSigning' {
            Name = 'Microsoft_network_server_Digitally_sign_communications_always'
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
        }

        # ================================
        # ACSC Medium Priority: User Rights Assignment
        # ================================
        UserRightsAssignment 'LogonAsService' {
            Policy   = 'Log_on_as_a_service'
            Identity = @('NT SERVICE\ALL SERVICES')
        }

        UserRightsAssignment 'DenyNetworkLogon' {
            Policy   = 'Deny_access_to_this_computer_from_the_network'
            Identity = @('Guests', 'Anonymous Logon')
        }

        UserRightsAssignment 'DenyLogonLocally' {
            Policy   = 'Deny_log_on_locally'
            Identity = @('Guests')
        }

        UserRightsAssignment 'DenyRemoteInteractiveLogon' {
            Policy   = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity = @('Guests', 'Local account')
        }

        UserRightsAssignment 'DenyLogonAsBatchJob' {
            Policy   = 'Deny_log_on_as_a_batch_job'
            Identity = @('Guests')
        }

        # ================================
        # ACSC Medium Priority: Anonymous Connections using SecurityOption DSC
        # ================================
        SecurityOption 'RestrictAnonymousAccess' {
            Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
        }

        SecurityOption 'NetworkAccessEveryoneIncludesAnonymous' {
            Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
            Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
        }

        # Guest logon over SMB (Group Policy preference - no DSC equivalent)
        Registry 'DisableGuestLogon' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueName   = 'AllowInsecureGuestAuth'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }

        # ================================
        # ACSC Medium Priority: Audit Policies
        # ================================
        AuditPolicySubcategory 'AuditAccountLogonSuccess' {
            Name      = 'Credential Validation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditAccountLogonFailure' {
            Name      = 'Credential Validation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditAccountManagementSuccess' {
            Name      = 'User Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditAccountManagementFailure' {
            Name      = 'User Account Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditLogonEventsSuccess' {
            Name      = 'Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditLogonEventsFailure' {
            Name      = 'Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditProcessTracking' {
            Name      = 'Process Creation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditPolicyChangeSuccess' {
            Name      = 'Audit Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditPolicyChangeFailure' {
            Name      = 'Audit Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditPrivilegeUseSuccess' {
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditPrivilegeUseFailure' {
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditSystemEventsSuccess' {
            Name      = 'Security System Extension'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditSystemEventsFailure' {
            Name      = 'Security System Extension'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditObjectAccess' {
            Name      = 'File System'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # Command line auditing (Group Policy preference)
        Registry 'EnableCommandLineAuditing' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            ValueName   = 'ProcessCreationIncludeCmdLine_Enabled'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        # ================================
        # ACSC Medium Priority: Event Log Configuration
        # ================================
        Registry 'SecurityLogSize' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            ValueName   = 'MaxSize'
            ValueType   = 'DWord'
            ValueData   = '2097152'  # 2GB
            Force       = $true
        }

        Registry 'SecurityLogRetention' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            ValueName   = 'Retention'
            ValueType   = 'String'
            ValueData   = '0'  # Overwrite as needed
            Force       = $true
        }

        Registry 'SystemLogSize' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            ValueName   = 'MaxSize'
            ValueType   = 'DWord'
            ValueData   = '65536'  # 64MB
            Force       = $true
        }

        Registry 'ApplicationLogSize' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
            ValueName   = 'MaxSize'
            ValueType   = 'DWord'
            ValueData   = '65536'  # 64MB
            Force       = $true
        }

        # ================================
        # ACSC Medium Priority: BitLocker Drive Encryption (Group Policy preferences)
        # ================================
        Registry 'BitLockerEnforceEncryption' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE'
            ValueName   = 'UseAdvancedStartup'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'BitLockerRequireStartupPIN' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE'
            ValueName   = 'UseTPMPIN'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'BitLockerMinimumPINLength' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE'
            ValueName   = 'MinimumPIN'
            ValueType   = 'DWord'
            ValueData   = '14'
            Force       = $true
        }

        # ================================
        # ACSC Medium Priority: Removable Storage Control (Group Policy preferences)
        # ================================
        Registry 'DenyRemovableStorageAccess' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'
            ValueName   = 'Deny_All'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'DenyUSBExecute' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'
            ValueName   = 'Deny_Execute'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'DenyUSBWrite' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'
            ValueName   = 'Deny_Write'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        # ================================
        # ACSC Medium Priority: Remote Desktop Security (Group Policy preferences)
        # ================================
        Registry 'RDPSecurityLayer' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
            ValueName   = 'SecurityLayer'
            ValueType   = 'DWord'
            ValueData   = '2'  # SSL
            Force       = $true
        }

        Registry 'RDPUserAuthentication' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
            ValueName   = 'UserAuthentication'
            ValueType   = 'DWord'
            ValueData   = '1'  # Require Network Level Authentication
            Force       = $true
        }

        Registry 'RDPEncryptionLevel' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
            ValueName   = 'MinEncryptionLevel'
            ValueType   = 'DWord'
            ValueData   = '3'  # High Level
            Force       = $true
        }

        Registry 'DisableRDPClipboard' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName   = 'fDisableClip'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'DisableRDPDriveRedirection' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName   = 'fDisableCdm'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        # ================================
        # ACSC Medium Priority: Session Locking (Group Policy preferences)
        # ================================
        Registry 'ScreenSaverTimeout' {
            Ensure      = 'Present'
            Key         = 'HKEY_CURRENT_USER\Control Panel\Desktop'
            ValueName   = 'ScreenSaveTimeOut'
            ValueType   = 'String'
            ValueData   = '900'  # 15 minutes
            Force       = $true
        }

        Registry 'ScreenSaverActive' {
            Ensure      = 'Present'
            Key         = 'HKEY_CURRENT_USER\Control Panel\Desktop'
            ValueName   = 'ScreenSaveActive'
            ValueType   = 'String'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'ScreenSaverSecure' {
            Ensure      = 'Present'
            Key         = 'HKEY_CURRENT_USER\Control Panel\Desktop'
            ValueName   = 'ScreenSaverIsSecure'
            ValueType   = 'String'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'MachineInactivityLimit' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'InactivityTimeoutSecs'
            ValueType   = 'DWord'
            ValueData   = '900'  # 15 minutes
            Force       = $true
        }

        # ================================
        # ACSC Medium Priority: Network Security
        # ================================
        Registry 'DisableIPSourceRouting' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName   = 'DisableIPSourceRouting'
            ValueType   = 'DWord'
            ValueData   = '2'
            Force       = $true
        }

        Registry 'EnableICMPRedirect' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName   = 'EnableICMPRedirect'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }

        Registry 'DisableNetBIOSOverTCPIP' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
            ValueName   = 'NoNameReleaseOnDemand'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        # ================================
        # ACSC Medium Priority: SMB Security (using SecurityOption DSC)
        # Note: SMB signing is now handled by SecurityOption DSC resources above
        # ================================

        # ================================
        # ACSC Medium Priority: Windows Features Management
        # ================================
        xWindowsOptionalFeature 'DisableSMB1Protocol' {
            Name   = 'SMB1Protocol'
            Ensure = 'Absent'
        }

        xWindowsOptionalFeature 'DisableTelnetClient' {
            Name   = 'TelnetClient'
            Ensure = 'Absent'
        }

        xWindowsOptionalFeature 'DisableTFTPClient' {
            Name   = 'TFTP'
            Ensure = 'Absent'
        }

        # ================================
        # ACSC Medium Priority: Additional Registry Settings
        # ================================
        Registry 'DisableAutoRun' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName   = 'NoDriveTypeAutoRun'
            ValueType   = 'DWord'
            ValueData   = '255'
            Force       = $true
        }

        Registry 'DisableAutoplay' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName   = 'NoAutoplayfornonVolume'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        # WebDAV service management - only configure if service exists
        Script 'DisableWebDAV' {
            GetScript = {
                $service = Get-Service -Name 'WebClient' -ErrorAction SilentlyContinue
                return @{ Result = if ($service) { $service.StartType } else { 'NotInstalled' } }
            }
            TestScript = {
                $service = Get-Service -Name 'WebClient' -ErrorAction SilentlyContinue
                if (-not $service) { return $true }  # Service doesn't exist, compliant
                return ($service.StartType -eq 'Disabled' -and $service.Status -eq 'Stopped')
            }
            SetScript = {
                $service = Get-Service -Name 'WebClient' -ErrorAction SilentlyContinue
                if ($service) {
                    Stop-Service -Name 'WebClient' -Force -ErrorAction SilentlyContinue
                    Set-Service -Name 'WebClient' -StartupType Disabled
                }
            }
        }

        Registry 'EnableLSAProtection' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName   = 'RunAsPPL'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        # Note: NTLM authentication level is already configured via SecurityOption DSC resource above

        # ================================
        # ACSC Medium Priority: PowerShell Security
        # ================================
        Registry 'PowerShellExecutionPolicy' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
            ValueName   = 'EnableScripts'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'PowerShellExecutionPolicyScope' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
            ValueName   = 'ExecutionPolicy'
            ValueType   = 'String'
            ValueData   = 'RemoteSigned'
            Force       = $true
        }

        Registry 'EnablePowerShellLogging' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
            ValueName   = 'EnableModuleLogging'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'EnablePowerShellScriptBlockLogging' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueName   = 'EnableScriptBlockLogging'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        # ================================
        # ACSC Medium Priority: Windows Services Management
        # ================================
        Service 'DisableRemoteRegistry' {
            Name        = 'RemoteRegistry'
            StartupType = 'Disabled'
            State       = 'Stopped'
            Ensure      = 'Present'
        }

        Service 'DisableRemoteAssistance' {
            Name        = 'SessionEnv'
            StartupType = 'Manual'
            State       = 'Stopped'
            Ensure      = 'Present'
        }

        # Telnet service - only configure if service exists
        Script 'DisableTelnet' {
            GetScript = {
                $service = Get-Service -Name 'TlntSvr' -ErrorAction SilentlyContinue
                return @{ Result = if ($service) { $service.StartType } else { 'NotInstalled' } }
            }
            TestScript = {
                $service = Get-Service -Name 'TlntSvr' -ErrorAction SilentlyContinue
                if (-not $service) { return $true }  # Service doesn't exist, compliant
                return ($service.StartType -eq 'Disabled' -and $service.Status -eq 'Stopped')
            }
            SetScript = {
                $service = Get-Service -Name 'TlntSvr' -ErrorAction SilentlyContinue
                if ($service) {
                    Stop-Service -Name 'TlntSvr' -Force -ErrorAction SilentlyContinue
                    Set-Service -Name 'TlntSvr' -StartupType Disabled
                }
            }
        }

        Service 'EnableWindowsFirewall' {
            Name        = 'MpsSvc'
            StartupType = 'Automatic'
            State       = 'Running'
            Ensure      = 'Present'
        }

        # ================================
        # ACSC Medium Priority: Group Policy Preferences (Registry-only settings)
        # Note: These settings use registry because they don't have DSC resource equivalents
        # ================================

        # Windows Firewall configuration
        Registry 'FirewallDomainProfile' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName   = 'EnableFirewall'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'FirewallPrivateProfile' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName   = 'EnableFirewall'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'FirewallPublicProfile' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName   = 'EnableFirewall'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        # Disable legacy network features
        Registry 'DisableNetBIOS' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
            ValueName   = 'NodeType'
            ValueType   = 'DWord'
            ValueData   = '2'  # Disable NetBIOS over TCP/IP
            Force       = $true
        }

        Registry 'DisableWPAD' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName   = 'DisableWPAD'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        # Microsoft Store configuration
        Registry 'DisableMicrosoftStore' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore'
            ValueName   = 'RemoveWindowsStore'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        # Windows Search and Cortana configuration
        Registry 'DisableCortana' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName   = 'AllowCortana'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }

        Registry 'DisableWebSearch' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName   = 'DisableWebSearch'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        # ================================
        # ACSC Medium Priority: Windows Copilot (September 2025 Addition)
        # ================================
        Registry 'DisableWindowsCopilot' {
            Ensure      = 'Present'
            Key         = 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsCopilot'
            ValueName   = 'TurnOffWindowsCopilot'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        # ================================
        # ACSC Medium Priority: Safe Mode Protection (September 2025 Addition)
        # ================================
        Registry 'SafeModeBlockNonAdmins' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'SafeModeBlockNonAdmins'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        # ================================
        # ACSC Medium Priority: Enhanced Printer Security (September 2025 Updates)
        # ================================
        Registry 'PrinterRPCPacketPrivacy' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'
            ValueName   = 'RpcAuthnLevelPrivacyEnabled'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'PrinterRedirectionGuard' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
            ValueName   = 'RedirectionguardPolicy'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'PrinterRPCConnectionProtocol' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'
            ValueName   = 'RpcProtocols'
            ValueType   = 'DWord'
            ValueData   = '5'  # RPC over TCP
            Force       = $true
        }

        Registry 'PrinterRPCAuthentication' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'
            ValueName   = 'RpcAuthentication'
            ValueType   = 'DWord'
            ValueData   = '0'  # Default (Negotiate)
            Force       = $true
        }

        Registry 'PrinterDriverSignatureValidation' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
            ValueName   = 'DriverSigningPolicy'
            ValueType   = 'DWord'
            ValueData   = '1'  # Allow all validly signed drivers
            Force       = $true
        }

        Registry 'PrinterQueueSpecificFiles' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
            ValueName   = 'CopyFilesPolicy'
            ValueType   = 'DWord'
            ValueData   = '1'  # Limit to color profiles only
            Force       = $true
        }
    }
}

# Generate the MOF file
ACSCMediumPriorityHardening -OutputPath (Join-Path $PSScriptRoot "ACSCMediumPriorityHardening")
