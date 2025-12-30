# ACSC Windows Hardening - Terraform Module

This Terraform module automates the deployment of Azure Machine Configuration policies for implementing ACSC (Australian Cyber Security Centre) Windows hardening guidelines.

## Features

The module automatically:
1. ✅ Creates an Azure Storage Account for DSC MOF packages
2. ✅ Downloads and uploads MOF files from GitHub releases
3. ✅ Generates SAS token links for secure package access
4. ✅ Creates Azure Policy machine configuration definitions
5. ✅ Creates Azure Policy assignments with managed identities
6. ✅ Assigns required roles to managed identities

## Prerequisites

- Terraform >= 1.0
- Azure CLI or authenticated Azure service principal
- Azure subscription with appropriate permissions:
  - Storage Account Contributor
  - Policy Contributor
  - Role Assignment Administrator
- Target Windows VMs must have:
  - Managed identity enabled
  - Guest Configuration extension installed (auto-installed by policy)

## Quick Start

### 1. Configure Variables

Copy the example variables file and customize it:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your values:

```hcl
subscription_id      = "your-subscription-id"
resource_group_name  = "rg-acsc-hardening"
storage_account_name = "stacschardening"  # Must be globally unique
```

### 2. Initialize Terraform

```bash
terraform init
```

### 3. Plan Deployment

```bash
terraform plan
```

### 4. Apply Configuration

```bash
terraform apply
```

### 5. Monitor Compliance

After deployment, monitor compliance in the Azure Portal:
- Navigate to **Azure Policy** → **Compliance**
- Initial evaluation takes 20-30 minutes
- Configurations are auto-corrected every 15 minutes (if using ApplyAndAutoCorrect mode)

## Variables

### Required Variables

| Variable | Type | Description |
|----------|------|-------------|
| `subscription_id` | string | Azure Subscription ID |
| `resource_group_name` | string | Name of the Azure Resource Group |
| `storage_account_name` | string | Storage account name (3-24 chars, lowercase alphanumeric, globally unique) |

### Optional Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `location` | string | `"Australia East"` | Azure region for resources |
| `container_name` | string | `"acsc-machine-configuration"` | Storage container name |
| `github_repo` | string | `"devnomadic/ACSC-WindowsHardening"` | GitHub repository for releases |
| `release_version` | string | `""` (latest) | GitHub release version (e.g., "v1.0.0") |
| `configuration_level` | string | `"All"` | Configuration level: `HighPriority`, `MediumPriority`, or `All` |
| `assignment_type` | string | `"ApplyAndAutoCorrect"` | Assignment type: `ApplyAndMonitor` or `ApplyAndAutoCorrect` |
| `sas_token_expiry_years` | number | `2` | SAS token validity period in years |
| `tags` | map(string) | See below | Resource tags |

**Default Tags:**
```hcl
{
  Environment = "Production"
  ManagedBy   = "Terraform"
  Purpose     = "ACSC-Windows-Hardening"
}
```

## Outputs

### Storage Information

| Output | Description |
|--------|-------------|
| `storage_account_name` | Name of the created storage account |
| `storage_account_id` | Resource ID of the storage account |
| `container_name` | Name of the storage container |
| `high_priority_package_url` | URL of the High Priority package blob |
| `medium_priority_package_url` | URL of the Medium Priority package blob |

### Package Information (Sensitive)

| Output | Description |
|--------|-------------|
| `high_priority_content_uri` | SAS token URI for High Priority package |
| `medium_priority_content_uri` | SAS token URI for Medium Priority package |
| `high_priority_content_hash` | SHA256 hash of High Priority package |
| `medium_priority_content_hash` | SHA256 hash of Medium Priority package |

### Policy Information

| Output | Description |
|--------|-------------|
| `high_priority_policy_id` | Resource ID of High Priority policy definition |
| `medium_priority_policy_id` | Resource ID of Medium Priority policy definition |
| `high_priority_assignment_id` | Resource ID of High Priority policy assignment |
| `medium_priority_assignment_id` | Resource ID of Medium Priority policy assignment |
| `high_priority_managed_identity_principal_id` | Principal ID of managed identity for High Priority |
| `medium_priority_managed_identity_principal_id` | Principal ID of managed identity for Medium Priority |

### Release Information

| Output | Description |
|--------|-------------|
| `release_version` | GitHub release version deployed |
| `release_name` | GitHub release name |

## Usage Examples

### Deploy All Configurations (Default)

```hcl
subscription_id      = "12345678-1234-1234-1234-123456789012"
resource_group_name  = "rg-acsc-hardening"
storage_account_name = "stacschardening"
configuration_level  = "All"
assignment_type      = "ApplyAndAutoCorrect"
```

### Deploy Only High Priority Configuration

```hcl
subscription_id      = "12345678-1234-1234-1234-123456789012"
resource_group_name  = "rg-acsc-hardening"
storage_account_name = "stacschardening"
configuration_level  = "HighPriority"
```

### Deploy Specific Release Version

```hcl
subscription_id      = "12345678-1234-1234-1234-123456789012"
resource_group_name  = "rg-acsc-hardening"
storage_account_name = "stacschardening"
release_version      = "v1.0.0"
```

### Audit-Only Mode (No Enforcement)

```hcl
subscription_id      = "12345678-1234-1234-1234-123456789012"
resource_group_name  = "rg-acsc-hardening"
storage_account_name = "stacschardening"
assignment_type      = "ApplyAndMonitor"
```

## Authentication

### Option 1: Azure CLI

```bash
az login
az account set --subscription "your-subscription-id"
terraform apply
```

### Option 2: Service Principal

```bash
export ARM_CLIENT_ID="your-client-id"
export ARM_CLIENT_SECRET="your-client-secret"
export ARM_SUBSCRIPTION_ID="your-subscription-id"
export ARM_TENANT_ID="your-tenant-id"
terraform apply
```

### Option 3: Managed Identity (Azure VM/Azure DevOps)

Terraform automatically uses managed identity when running in Azure.

## Assignment Types

### ApplyAndMonitor
- Configuration is applied **once** when the policy is first assigned
- Drift is **monitored** but not automatically corrected
- Non-compliant resources must be **manually remediated**
- Use for testing or when you want manual control

### ApplyAndAutoCorrect (Recommended)
- Configuration is applied initially
- Agent checks compliance **every 15 minutes**
- Drift is **automatically corrected**
- Provides continuous compliance enforcement
- Recommended for production environments

## Configuration Levels

### HighPriority
Implements critical ACSC recommendations:
- Application control
- Credential protection (Credential Guard)
- Attack Surface Reduction (ASR)
- User Account Control (UAC)
- Secure Boot
- And more...

### MediumPriority
Implements additional hardening:
- Account lockout policy
- Password policy
- BitLocker encryption
- Windows Firewall
- PowerShell security
- And more...

### All
Deploys both High and Medium priority configurations.

## Compliance Monitoring

### Azure Portal
1. Navigate to **Azure Policy** → **Compliance**
2. Filter by resource group or policy name
3. View detailed compliance status per resource

### Azure CLI
```bash
# Check policy compliance state
az policy state list --resource-group rg-acsc-hardening

# View guest configuration assignments
az vm guest-assignment list --resource-group rg-acsc-hardening
```

### PowerShell
```powershell
# Check policy compliance
Get-AzPolicyState -ResourceGroupName "rg-acsc-hardening"

# View guest configuration assignments
Get-AzGuestConfigurationAssignment -ResourceGroupName "rg-acsc-hardening"
```

## Troubleshooting

### Storage Account Name Already Exists

**Error:** `Storage account name is already taken`

**Solution:** Storage account names must be globally unique. Choose a different name:
```hcl
storage_account_name = "stacschardening2024"
```

### Policy Assignment Identity Not Created

**Error:** Managed identity was not automatically created

**Solution:** This can occur due to Azure API delays. Wait 5-10 minutes and run:
```bash
terraform apply -refresh-only
```

### Compliance Not Showing

**Issue:** Policy shows as "Not started" after 30 minutes

**Solution:** 
1. Ensure VMs have managed identity enabled
2. Check Guest Configuration extension is installed
3. Verify VMs are Windows (not Linux)
4. Check Azure Policy evaluation status

### SAS Token Expired

**Issue:** Configuration downloads fail with 403 errors

**Solution:** Re-run terraform to generate new SAS tokens:
```bash
terraform apply -replace="data.azurerm_storage_account_blob_container_sas.high_priority[0]"
```

## Clean Up

To remove all resources created by this module:

```bash
terraform destroy
```

**Note:** This will:
- Delete policy assignments
- Delete policy definitions
- Delete storage account and all packages
- Remove role assignments

## Security Considerations

- Storage account uses **private containers** (no public access)
- SAS tokens are generated with **read-only** permissions
- SAS tokens are marked as **sensitive** in Terraform outputs
- Managed identities follow **principle of least privilege**
- TLS 1.2 is enforced for storage account

## Cost Estimation

Approximate monthly costs (Australia East region):

| Resource | Estimated Cost |
|----------|----------------|
| Storage Account (LRS) | ~$0.50/month |
| Policy Assignments | Free |
| Guest Configuration Extension | Free |
| **Total** | **~$0.50/month** |

*Note: Actual costs may vary based on storage usage and data transfer.*

## Comparison with PowerShell Deployment

| Feature | PowerShell Script | Terraform Module |
|---------|-------------------|------------------|
| Infrastructure as Code | ❌ | ✅ |
| State Management | ❌ | ✅ |
| Idempotent | Partial | ✅ |
| Version Control Friendly | ❌ | ✅ |
| CI/CD Integration | Moderate | Easy |
| Rollback Support | ❌ | ✅ |
| Cross-platform | Windows only | All platforms |

## Support

- **Issues:** [GitHub Issues](https://github.com/devnomadic/ACSC-WindowsHardening/issues)
- **ACSC Guidelines:** [ACSC Windows Hardening](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/hardening-microsoft-windows-10-and-windows-11-workstations)
- **Azure Policy:** [Azure Machine Configuration Documentation](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/overview)

## Contributing

Contributions are welcome! Please submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.
