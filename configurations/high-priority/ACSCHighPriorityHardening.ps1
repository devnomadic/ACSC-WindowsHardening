Configuration ACSCHighPriorityHardening {
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
        # ACSC High Priority: Prerequisites
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
        # ACSC High Priority: Account Policies using SecurityPolicyDsc
        # ================================
        AccountPolicy 'AccountSecurityPolicy' {
            Name                        = 'AccountSecurityPolicy'
            # Password Policy
            Enforce_password_history    = 24
            Maximum_password_age        = 60
            Minimum_password_age        = 1
            Minimum_password_length     = 14
            Password_must_meet_complexity_requirements = 'Enabled'
            Store_passwords_using_reversible_encryption = 'Disabled'
            # Account Lockout Policy (ACSC: locked until admin unlocks)
            Account_lockout_duration      = 0  # 0 = must be unlocked by administrator
            Account_lockout_threshold     = 5  # Lock after 5 failed attempts
            Reset_account_lockout_counter_after = 0  # Must be 0 when duration is 0 (Windows constraint)
        }

        # ================================
        # ACSC High Priority: Security Options using SecurityPolicyDsc
        # ================================
        SecurityOption 'InteractiveLogon' {
            Name                                             = 'InteractiveLogon'
            Interactive_logon_Do_not_display_last_user_name = 'Enabled'
            Interactive_logon_Do_not_require_CTRL_ALT_DEL   = 'Disabled'
            Interactive_logon_Machine_inactivity_limit      = 900
            Interactive_logon_Message_text_for_users_attempting_to_log_on = 'This computer system is for authorized users only.'
            Interactive_logon_Message_title_for_users_attempting_to_log_on = 'WARNING: Authorized Access Only'
            Interactive_logon_Prompt_user_to_change_password_before_expiration = 14
            Interactive_logon_Smart_card_removal_behavior   = 'Lock workstation'
        }

        # Note: Administrator and Guest account status/rename settings removed
        # These cause conflicts and should be managed through other means
        SecurityOption 'AccountPasswordPolicy' {
            Name = 'AccountPasswordPolicy'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
        }

        SecurityOption 'NetworkSecurity' {
            Name                                                                      = 'NetworkSecurity'
            Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM   = 'Enabled'
            Network_security_Allow_LocalSystem_NULL_session_fallback                = 'Disabled'
            Network_security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
            Network_security_Configure_encryption_types_allowed_for_Kerberos        = @('AES128_HMAC_SHA1', 'AES256_HMAC_SHA1', 'FUTURE')
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
            Network_security_Force_logoff_when_logon_hours_expire                   = 'Enabled'
            Network_security_LAN_Manager_authentication_level                       = 'Send NTLMv2 responses only. Refuse LM & NTLM'
            Network_security_LDAP_client_signing_requirements                       = 'Require signing'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
            Network_security_Restrict_NTLM_Add_remote_server_exceptions_for_NTLM_authentication = ''
            Network_security_Restrict_NTLM_Add_server_exceptions_in_this_domain    = ''
        }

        SecurityOption 'DomainControllerSecurity' {
            Name                                                                 = 'DomainControllerSecurity'
            Domain_controller_Allow_server_operators_to_schedule_tasks          = 'Disabled'
            Domain_controller_LDAP_server_signing_requirements                   = 'Require signing'
            Domain_controller_Refuse_machine_account_password_changes            = 'Disabled'
        }

        SecurityOption 'SystemSecurity' {
            Name                                                                      = 'SystemSecurity'
            System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User input is not required when new keys are stored and used'
            System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
            System_objects_Require_case_insensitivity_for_non_Windows_subsystems    = 'Enabled'
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
            System_settings_Optional_subsystems                                     = ''
            System_settings_Use_Certificate_Rules_on_Windows_Executables_for_Software_Restriction_Policies = 'Enabled'
        }

        # ================================
        # ACSC High Priority: User Rights Assignment using SecurityPolicyDsc
        # ================================
        UserRightsAssignment 'SeNetworkLogonRight' {
            Policy   = 'Access_this_computer_from_the_network'
            Identity = @('Administrators', 'Remote Desktop Users')
        }

        UserRightsAssignment 'SeBatchLogonRight' {
            Policy   = 'Log_on_as_a_batch_job'
            Identity = @('Administrators')
        }

        UserRightsAssignment 'SeServiceLogonRight' {
            Policy   = 'Log_on_as_a_service'
            Identity = @('NT SERVICE\ALL SERVICES')
        }

        UserRightsAssignment 'SeDenyNetworkLogonRight' {
            Policy   = 'Deny_access_to_this_computer_from_the_network'
            Identity = @('Guests')
        }

        UserRightsAssignment 'SeDenyBatchLogonRight' {
            Policy   = 'Deny_log_on_as_a_batch_job'
            Identity = @('Guests')
        }

        UserRightsAssignment 'SeDenyServiceLogonRight' {
            Policy   = 'Deny_log_on_as_a_service'
            Identity = @('Guests')
        }

        UserRightsAssignment 'SeDenyInteractiveLogonRight' {
            Policy   = 'Deny_log_on_locally'
            Identity = @('Guests')
        }

        UserRightsAssignment 'SeDenyRemoteInteractiveLogonRight' {
            Policy   = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity = @('Guests', 'Local account')
        }

        UserRightsAssignment 'SeBackupPrivilege' {
            Policy   = 'Back_up_files_and_directories'
            Identity = @('Administrators')
        }

        UserRightsAssignment 'SeRestorePrivilege' {
            Policy   = 'Restore_files_and_directories'
            Identity = @('Administrators')
        }

        UserRightsAssignment 'SeShutdownPrivilege' {
            Policy   = 'Shut_down_the_system'
            Identity = @('Administrators', 'Users')
        }

        UserRightsAssignment 'SeTakeOwnershipPrivilege' {
            Policy   = 'Take_ownership_of_files_or_other_objects'
            Identity = @('Administrators')
        }

        # ================================
        # ACSC High Priority: UAC Settings using SecurityOption DSC
        # ================================
        SecurityOption 'UAC_AdminApprovalMode' {
            Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
        }

        SecurityOption 'UAC_PromptForCredentials' {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for credentials on the secure desktop'
        }

        SecurityOption 'UAC_BuiltinAdminApprovalMode' {
            Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
        }

        SecurityOption 'UAC_DenyElevationRequests' {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
        }

        # ================================
        # ACSC High Priority: Registry-based Group Policy Settings
        # Note: These settings use registry because they don't have DSC resource equivalents
        # ================================

        # ================================
        # ACSC High Priority: Audit Policies using AuditPolicyDsc
        # ================================
        AuditPolicySubcategory 'AuditCredentialValidation' {
            Name      = 'Credential Validation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditCredentialValidationFailure' {
            Name      = 'Credential Validation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditApplicationGroupManagement' {
            Name      = 'Application Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditApplicationGroupManagementFailure' {
            Name      = 'Application Group Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditSecurityGroupManagement' {
            Name      = 'Security Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditSecurityGroupManagementFailure' {
            Name      = 'Security Group Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditUserAccountManagement' {
            Name      = 'User Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditUserAccountManagementFailure' {
            Name      = 'User Account Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditLogon' {
            Name      = 'Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditLogonFailure' {
            Name      = 'Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditLogoff' {
            Name      = 'Logoff'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditSpecialLogon' {
            Name      = 'Special Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditProcessCreation' {
            Name      = 'Process Creation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditAuditPolicyChange' {
            Name      = 'Audit Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditAuditPolicyChangeFailure' {
            Name      = 'Audit Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditAuthenticationPolicyChange' {
            Name      = 'Authentication Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditSensitivePrivilegeUse' {
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditSensitivePrivilegeUseFailure' {
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditIPSecDriver' {
            Name      = 'IPSec Driver'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditIPSecDriverFailure' {
            Name      = 'IPSec Driver'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditSecuritySystemExtension' {
            Name      = 'Security System Extension'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditSecuritySystemExtensionFailure' {
            Name      = 'Security System Extension'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditSystemIntegrity' {
            Name      = 'System Integrity'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'AuditSystemIntegrityFailure' {
            Name      = 'System Integrity'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # ================================
        # ACSC High Priority: Windows Features using WindowsOptionalFeature
        # ================================
        Script 'DisableSMB1Protocol' {
            GetScript = {
                $Feature = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue
                return @{ Result = if ($Feature) { $Feature.State } else { 'NotPresent' } }
            }
            TestScript = {
                $Feature = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue
                if (-not $Feature) { return $true }
                return ($Feature.State -eq 'Disabled' -or $Feature.State -eq 'DisabledWithPayloadRemoved')
            }
            SetScript = {
                Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart -ErrorAction Stop
            }
        }

        Script 'DisableTelnetClient' {
            GetScript = {
                $Feature = Get-WindowsOptionalFeature -Online -FeatureName 'TelnetClient' -ErrorAction SilentlyContinue
                return @{ Result = if ($Feature) { $Feature.State } else { 'NotPresent' } }
            }
            TestScript = {
                $Feature = Get-WindowsOptionalFeature -Online -FeatureName 'TelnetClient' -ErrorAction SilentlyContinue
                if (-not $Feature) { return $true }
                return ($Feature.State -eq 'Disabled' -or $Feature.State -eq 'DisabledWithPayloadRemoved')
            }
            SetScript = {
                Disable-WindowsOptionalFeature -Online -FeatureName 'TelnetClient' -NoRestart -ErrorAction Stop
            }
        }

        Script 'DisableTFTPClient' {
            GetScript = {
                $Feature = Get-WindowsOptionalFeature -Online -FeatureName 'TFTP' -ErrorAction SilentlyContinue
                return @{ Result = if ($Feature) { $Feature.State } else { 'NotPresent' } }
            }
            TestScript = {
                $Feature = Get-WindowsOptionalFeature -Online -FeatureName 'TFTP' -ErrorAction SilentlyContinue
                if (-not $Feature) { return $true }
                return ($Feature.State -eq 'Disabled' -or $Feature.State -eq 'DisabledWithPayloadRemoved')
            }
            SetScript = {
                Disable-WindowsOptionalFeature -Online -FeatureName 'TFTP' -NoRestart -ErrorAction Stop
            }
        }

        # ================================
        # ACSC High Priority: Windows Services using Service
        # ================================
        Service 'WindowsDefender' {
            Name        = 'WinDefend'
            StartupType = 'Automatic'
            State       = 'Running'
            Ensure      = 'Present'
        }

        Service 'WindowsFirewall' {
            Name        = 'MpsSvc'
            StartupType = 'Automatic'
            State       = 'Running'
            Ensure      = 'Present'
        }

        # Security Center service - only configure if exists
        Script 'SecurityCenter' {
            GetScript = {
                $service = Get-Service -Name 'wscsvc' -ErrorAction SilentlyContinue
                return @{ Result = if ($service) { $service.StartType } else { 'NotInstalled' } }
            }
            TestScript = {
                $service = Get-Service -Name 'wscsvc' -ErrorAction SilentlyContinue
                if (-not $service) { return $true }  # Service doesn't exist, compliant
                return ($service.StartType -eq 'Automatic' -and $service.Status -eq 'Running')
            }
            SetScript = {
                $service = Get-Service -Name 'wscsvc' -ErrorAction SilentlyContinue
                if ($service) {
                    Set-Service -Name 'wscsvc' -StartupType Automatic
                    Start-Service -Name 'wscsvc' -ErrorAction SilentlyContinue
                }
            }
        }

        Service 'DisableRemoteRegistry' {
            Name        = 'RemoteRegistry'
            StartupType = 'Disabled'
            State       = 'Stopped'
            Ensure      = 'Present'
        }

        Service 'DisableRouting' {
            Name        = 'RemoteAccess'
            StartupType = 'Disabled'
            State       = 'Stopped'
            Ensure      = 'Present'
        }

        Service 'DisableSSDP' {
            Name        = 'SSDPSRV'
            StartupType = 'Disabled'
            State       = 'Stopped'
            Ensure      = 'Present'
        }

        # ================================
        # ACSC High Priority: Registry-based Group Policy Settings
        # ================================
        
        # User Account Control (UAC) - Group Policy settings
        Registry 'UAC_AdminApprovalMode' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'EnableLUA'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'UAC_PromptForCredentials' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'ConsentPromptBehaviorAdmin'
            ValueType   = 'DWord'
            ValueData   = '1'  # Prompt for credentials on the secure desktop
            Force       = $true
        }

        Registry 'UAC_BuiltinAdminApprovalMode' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'FilterAdministratorToken'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'UAC_DenyElevationRequests' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName   = 'ConsentPromptBehaviorUser'
            ValueType   = 'DWord'
            ValueData   = '0'  # Automatically deny elevation requests
            Force       = $true
        }

        # Attack Surface Reduction (ASR) Rules
        Registry 'ASR_BlockAbuseOfExploitedVulnerableSignedDrivers' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName   = '56a863a9-875e-4185-98a7-b882c64b5ce5'
            ValueType   = 'DWord'
            ValueData   = '1'  # Block
            Force       = $true
        }

        Registry 'ASR_BlockOfficeAppsCreatingChildProcesses' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName   = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
            ValueType   = 'String'
            ValueData   = '1'  # Block all Office applications from creating child processes
            Force       = $true
        }

        Registry 'ASR_BlockCredentialStealing' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName   = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
            ValueType   = 'String'
            ValueData   = '1'  # Block credential stealing from LSASS
            Force       = $true
        }

        Registry 'ASR_BlockExecutableContentFromEmail' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName   = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
            ValueType   = 'String'
            ValueData   = '1'  # Block executable content from email client and webmail
            Force       = $true
        }

        Registry 'ASR_BlockJavaScriptVBScript' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName   = 'd3e037e1-3eb8-44c8-a917-57927947596d'
            ValueType   = 'String'
            ValueData   = '1'  # Block JavaScript or VBScript from launching downloaded executable content
            Force       = $true
        }

        Registry 'ASR_UseAdvancedProtectionAgainstRansomware' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueName   = 'c1db55ab-c21a-4637-bb3f-a12568109d35'
            ValueType   = 'String'
            ValueData   = '1'  # Use advanced protection against ransomware
            Force       = $true
        }

        # Credential Protection
        Registry 'DisableWDigest' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
            ValueName   = 'UseLogonCredential'
            ValueType   = 'DWord'
            ValueData   = '0'
            Force       = $true
        }

        Registry 'EnableCredentialGuard' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard'
            ValueName   = 'EnableVirtualizationBasedSecurity'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'CredentialGuardConfiguration' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA'
            ValueName   = 'LsaCfgFlags'
            ValueType   = 'DWord'
            ValueData   = '1'  # Enabled with UEFI lock
            Force       = $true
        }

        # Controlled Folder Access
        Registry 'ControlledFolderAccessEnable' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access'
            ValueName   = 'EnableControlledFolderAccess'
            ValueType   = 'DWord'
            ValueData   = '1'  # Enable Controlled Folder Access
            Force       = $true
        }

        # Early Launch Antimalware (ELAM)
        Registry 'ELAMBootDriverPolicy' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            ValueName   = 'DriverLoadPolicy'
            ValueType   = 'DWord'
            ValueData   = '3'  # Good, unknown and bad but critical
            Force       = $true
        }

        # Exploit Protection
        Registry 'EnableDEP' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName   = 'NoDataExecutionPrevention'
            ValueType   = 'DWord'
            ValueData   = '0'  # Enable DEP
            Force       = $true
        }

        Registry 'EnableSEHOP' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            ValueName   = 'DisableExceptionChainValidation'
            ValueType   = 'DWord'
            ValueData   = '0'  # Enable SEHOP
            Force       = $true
        }

        # Microsoft Defender Configuration
        Registry 'DefenderRealTimeProtection' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
            ValueName   = 'DisableRealtimeMonitoring'
            ValueType   = 'DWord'
            ValueData   = '0'  # Enable real-time protection
            Force       = $true
        }

        Registry 'DefenderCloudProtection' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
            ValueName   = 'SpynetReporting'
            ValueType   = 'DWord'
            ValueData   = '2'  # Advanced MAPS
            Force       = $true
        }

        Registry 'DefenderSubmitSamples' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
            ValueName   = 'SubmitSamplesConsent'
            ValueType   = 'DWord'
            ValueData   = '1'  # Send all samples
            Force       = $true
        }

        # Local Administrator Password Solution (LAPS)
        Registry 'LAPSEnable' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd'
            ValueName   = 'AdmPwdEnabled'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'LAPSPasswordComplexity' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd'
            ValueName   = 'PasswordComplexity'
            ValueType   = 'DWord'
            ValueData   = '4'  # Large letters + small letters + numbers + specials
            Force       = $true
        }

        Registry 'LAPSPasswordLength' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd'
            ValueName   = 'PasswordLength'
            ValueType   = 'DWord'
            ValueData   = '30'
            Force       = $true
        }

        Registry 'LAPSPasswordAge' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd'
            ValueName   = 'PasswordAgeDays'
            ValueType   = 'DWord'
            ValueData   = '365'
            Force       = $true
        }

        # Windows Update Configuration
        Registry 'WindowsUpdateAutoInstall' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            ValueName   = 'AUOptions'
            ValueType   = 'DWord'
            ValueData   = '4'  # Auto download and schedule install
            Force       = $true
        }

        Registry 'WindowsUpdateScheduledInstallDay' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            ValueName   = 'ScheduledInstallDay'
            ValueType   = 'DWord'
            ValueData   = '0'  # Every day
            Force       = $true
        }

        Registry 'DisablePauseUpdates' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
            ValueName   = 'SetDisablePauseUXAccess'
            ValueType   = 'DWord'
            ValueData   = '1'  # Remove access to pause updates
            Force       = $true
        }

        # Autoplay and AutoRun Disabled
        Registry 'DisableAutoplay' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueName   = 'NoDriveTypeAutoRun'
            ValueType   = 'DWord'
            ValueData   = '255'  # Disable for all drives
            Force       = $true
        }

        Registry 'DisableAutoRun' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName   = 'NoAutoplayfornonVolume'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        # Windows Hello for Business
        Registry 'EnableWindowsHelloForBusiness' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName   = 'AllowDomainPINLogon'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'WindowsHelloPINLength' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity'
            ValueName   = 'MinimumPINLength'
            ValueType   = 'DWord'
            ValueData   = '6'
            Force       = $true
        }

        Registry 'WindowsHelloPINExpiration' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity'
            ValueName   = 'Expiration'
            ValueType   = 'DWord'
            ValueData   = '365'
            Force       = $true
        }

        # Command line auditing
        Registry 'EnableCommandLineAuditing' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            ValueName   = 'ProcessCreationIncludeCmdLine_Enabled'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        # PowerShell Security
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

        Registry 'EnablePowerShellModuleLogging' {
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

        Registry 'EnablePowerShellTranscription' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueName   = 'EnableTranscripting'
            ValueType   = 'DWord'
            ValueData   = '1'
            Force       = $true
        }

        Registry 'PowerShellTranscriptionOutputDirectory' {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueName   = 'OutputDirectory'
            ValueType   = 'String'
            ValueData   = 'C:\PowerShellLogs'
            Force       = $true
        }
    }
}

# Generate the MOF file
ACSCHighPriorityHardening -OutputPath (Join-Path $PSScriptRoot "ACSCHighPriorityHardening")
