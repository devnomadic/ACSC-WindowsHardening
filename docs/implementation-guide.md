# ACSC Windows Hardening Implementation Guide

## Overview

This guide provides step-by-step instructions for implementing the Australian Cyber Security Centre (ACSC) Windows hardening guidelines using Azure Machine Configuration.

## Prerequisites

### Azure Requirements
- Azure subscription with appropriate permissions
- Azure Policy and Machine Configuration enabled
- Resource group for storing configuration packages
- Storage account for hosting packages

### PowerShell Requirements
- PowerShell 5.1 or PowerShell Core 7.x
- Az PowerShell modules
- GuestConfiguration PowerShell module

### Target Machine Requirements
- Windows 10 (supported versions)
- Windows 11 (all versions)
- Windows Server 2016, 2019, 2022
- Azure VM or Arc-enabled server
- System-assigned managed identity
- Machine Configuration extension installed

## Installation Steps

### Step 1: Install Required PowerShell Modules

```powershell
# Install required modules
Install-Module Az.Accounts -Force -AllowClobber
Install-Module Az.Resources -Force -AllowClobber
Install-Module Az.Storage -Force -AllowClobber
Install-Module Az.PolicyInsights -Force -AllowClobber
Install-Module GuestConfiguration -Force -AllowClobber
```

### Step 2: Clone Repository

```powershell
git clone https://github.com/your-org/ACSC-WindowsHardening.git
cd ACSC-WindowsHardening
```

### Step 3: Create Machine Configuration Packages

```powershell
# Create all packages
.\scripts\New-ACSCMachineConfigurationPackage.ps1 -ConfigurationLevel All

# Or create specific priority level
.\scripts\New-ACSCMachineConfigurationPackage.ps1 -ConfigurationLevel HighPriority
```

### Step 4: Deploy to Azure

```powershell
# Deploy with audit mode (recommended for initial deployment)
.\scripts\Deploy-ACSCToAzure.ps1 -SubscriptionId "your-subscription-id" `
                                  -ResourceGroupName "acsc-hardening-rg" `
                                  -StorageAccountName "acscstorage123" `
                                  -Location "Australia East" `
                                  -EnforcementMode "Audit"

# Deploy with enforcement mode (for production deployment)
.\scripts\Deploy-ACSCToAzure.ps1 -SubscriptionId "your-subscription-id" `
                                  -ResourceGroupName "acsc-hardening-rg" `
                                  -StorageAccountName "acscstorage123" `
                                  -Location "Australia East" `
                                  -EnforcementMode "ApplyAndMonitor"
```

## Configuration Levels

### High Priority Configurations

The high priority configurations implement the most critical security settings:

- **User Account Control (UAC)**: Enhanced UAC settings for privilege escalation
- **Attack Surface Reduction (ASR)**: Microsoft Defender ASR rules
- **Credential Protection**: Credential Guard and WDigest configuration
- **Controlled Folder Access**: Ransomware protection
- **Secure Desktop**: Secure credential entry
- **Early Launch Antimalware**: Boot-time malware protection
- **Exploit Protection**: DEP, ASLR, and SEHOP
- **Microsoft Defender**: Real-time protection and cloud protection
- **LAPS**: Local Administrator Password Solution
- **Windows Update**: Automatic update configuration
- **Autoplay/AutoRun**: Disabled to prevent malware execution
- **Windows Hello for Business**: Multi-factor authentication

### Medium Priority Configurations

The medium priority configurations provide additional security hardening:

- **Account Lockout Policy**: Brute force protection
- **Anonymous Connections**: Restrict anonymous access
- **Audit Event Management**: Enhanced logging
- **BitLocker**: Drive encryption configuration
- **Network Authentication**: Secure authentication protocols
- **Password Policy**: Strong password requirements
- **PowerShell Security**: Script execution policy and logging
- **Removable Storage**: USB and removable media control
- **Remote Desktop**: Secure RDP configuration
- **Session Locking**: Automatic screen lock
- **SMB Security**: Secure file sharing
- **Windows Firewall**: Network protection
- **Legacy Features**: Disable insecure protocols

## Enforcement Modes

### Audit Mode
- **Purpose**: Assess current compliance without making changes
- **Use Case**: Initial assessment, testing, compliance reporting
- **Impact**: No configuration changes applied to machines
- **Recommendation**: Use for initial deployment and ongoing monitoring

### Apply and Monitor Mode
- **Purpose**: Apply configurations and monitor for drift
- **Use Case**: Production environments where compliance is required
- **Impact**: Configurations applied once, then monitored
- **Recommendation**: Use for stable production environments

### Apply and Auto-Correct Mode
- **Purpose**: Apply configurations and automatically correct drift
- **Use Case**: High-security environments requiring constant compliance
- **Impact**: Configurations continuously enforced
- **Recommendation**: Use with caution, test thoroughly first

## Monitoring and Compliance

### Azure Policy Dashboard
- Navigate to Azure Policy in the Azure portal
- View compliance summary and details
- Drill down to specific non-compliant resources
- Review compliance over time

### Guest Configuration Reports
- View detailed per-setting compliance
- Access guest assignment reports
- Review configuration drift detection
- Monitor remediation activities

### Azure Resource Graph Queries

```kusto
// Get compliance status for all ACSC configurations
PolicyResources
| where type == "microsoft.guestconfiguration/guestconfigurationassignments"
| where name has "ACSC"
| project name, resourceGroup, complianceStatus, assignmentHash
| order by name

// Get non-compliant machines
PolicyResources
| where type == "microsoft.guestconfiguration/guestconfigurationassignments"
| where name has "ACSC"
| where properties.complianceStatus != "Compliant"
| project name, resourceGroup, complianceStatus, lastComplianceStatusChecked
```

## Troubleshooting

### Common Issues

#### Package Creation Failures
- **Issue**: DSC configuration compilation errors
- **Solution**: Check DSC module dependencies and syntax
- **Command**: `Test-DscConfiguration -Path ./configurations/`

#### Policy Assignment Failures
- **Issue**: Insufficient permissions
- **Solution**: Ensure account has Policy Contributor role
- **Permissions**: `Microsoft.Authorization/policyDefinitions/write`

#### Compliance Evaluation Delays
- **Issue**: Policy evaluation takes time
- **Solution**: Wait up to 30 minutes for initial evaluation
- **Command**: `Start-AzPolicyComplianceScan -ResourceGroupName "rg-name"`

#### Guest Configuration Extension Issues
- **Issue**: Extension not installed on target machines
- **Solution**: Deploy prerequisites policy initiative
- **Policy**: "Deploy prerequisites to enable Guest Configuration policies on virtual machines"

### Log Locations

#### Windows Machines
- **Azure VM**: `C:\ProgramData\GuestConfig\gc_agent_logs\gc_agent.log`
- **Arc-enabled**: `C:\ProgramData\GuestConfig\arc_policy_logs\gc_agent.log`

#### Debugging Commands

```powershell
# Check policy compliance
Get-AzPolicyState -ResourceGroupName "your-rg" | Where-Object {$_.PolicyDefinitionName -like "*ACSC*"}

# View guest configuration assignments
Get-AzGuestConfigurationAssignment -ResourceGroupName "your-rg"

# Check machine configuration extension status
Get-AzVMExtension -ResourceGroupName "your-rg" -VMName "your-vm"
```

## Security Considerations

### Phased Deployment Strategy
1. **Phase 1**: Deploy in audit mode to assess current state
2. **Phase 2**: Deploy high priority configurations in apply mode
3. **Phase 3**: Deploy medium priority configurations in apply mode
4. **Phase 4**: Enable auto-correct mode for critical settings

### Testing Recommendations
- Test configurations in development environment first
- Verify business application compatibility
- Document any required exceptions
- Establish rollback procedures

### Exception Management
- Document any configuration exceptions
- Implement compensating controls for exceptions
- Regularly review and validate exceptions
- Use Azure Policy exemptions for documented exceptions

## Best Practices

### Configuration Management
- Use version control for all configurations
- Implement change management processes
- Document all customizations
- Maintain configuration baselines

### Monitoring and Alerting
- Set up Azure Monitor alerts for compliance changes
- Implement regular compliance reporting
- Monitor for configuration drift
- Review compliance trends over time

### Maintenance
- Regularly update machine configuration packages
- Review and update ACSC guidelines alignment
- Test new Azure Machine Configuration features
- Maintain documentation and procedures

## Support and Resources

### Microsoft Documentation
- [Azure Machine Configuration Overview](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/overview)
- [Create custom machine configuration package artifacts](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/how-to/develop-custom-package/overview)

### ACSC Resources
- [ACSC Windows Hardening Guidelines](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/hardening-microsoft-windows-10-and-windows-11-workstations)
- [Essential Eight Strategies](https://www.cyber.gov.au/resources-business-and-government/essential-cybersecurity/essential-eight)

### Community Support
- [Azure Policy GitHub Repository](https://github.com/Azure/azure-policy)
- [PowerShell DSC Community](https://github.com/PowerShell/PowerShell-DSC)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
