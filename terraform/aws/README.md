# ACSC Windows Hardening - AWS Terraform Module

✅ **Status: Available**

This module automates the deployment of ACSC (Australian Cyber Security Centre) Windows hardening configurations to AWS EC2 instances using AWS Systems Manager and related services.

## Features

The AWS module provides:

1. ✅ **S3 Bucket for DSC Packages** - Secure storage for MOF files with versioning
2. ✅ **GitHub Release Integration** - Automatic download and upload of hardening packages
3. ✅ **SSM Documents** - SSM documents for DSC configuration application
4. ✅ **State Manager Associations** - Automated configuration application and drift remediation
5. ✅ **IAM Roles and Policies** - Proper permissions for EC2 instances
6. 🔄 **Compliance Monitoring** - Use AWS Config rules for continuous compliance checking (manual setup)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    GitHub Release                        │
│              (DSC MOF Packages + Hashes)                 │
└────────────────────┬────────────────────────────────────┘
                     │
                     ↓ (Terraform downloads)
┌─────────────────────────────────────────────────────────┐
│                     S3 Bucket                            │
│         - High Priority Package (ZIP)                    │
│         - Medium Priority Package (ZIP)                  │
│         - Pre-signed URLs (configurable expiry)          │
└────────────────────┬────────────────────────────────────┘
                     │
                     ↓ (EC2 instances download)
┌─────────────────────────────────────────────────────────┐
│              Systems Manager State Manager               │
│   - SSM Document (AWS-ApplyDSCMofs)                     │
│   - State Manager Associations                           │
│   - Schedule: Auto-remediation (configurable)           │
└────────────────────┬────────────────────────────────────┘
                     │
                     ↓ (applies configuration)
┌─────────────────────────────────────────────────────────┐
│                  Windows EC2 Instances                   │
│   - SSM Agent installed                                  │
│   - IAM Instance Profile attached                        │
│   - ACSC hardening configurations applied                │
└────────────────────┬────────────────────────────────────┘
                     │
                     ↓ (reports compliance)
┌─────────────────────────────────────────────────────────┐
│             AWS Config / Systems Manager                 │
│                 Compliance Dashboard                     │
└─────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Configure Variables

Copy the example variables file and customize it:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your values:

```hcl
region         = "ap-southeast-2"
s3_bucket_name = "acsc-hardening-packages"  # Must be globally unique
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

### 5. Tag EC2 Instances

Tag your Windows EC2 instances to receive hardening:

```bash
aws ec2 create-tags --resources i-1234567890abcdef0 --tags Key=ACSC-Hardening,Value=Enabled
```

Or via Terraform:

```hcl
resource "aws_instance" "windows" {
  # ... other configuration ...
  
  iam_instance_profile = module.acsc_hardening.iam_instance_profile_name
  
  tags = {
    ACSC-Hardening = "Enabled"
  }
}
```

### 6. Monitor Compliance

Check compliance in AWS Systems Manager Console:
- Navigate to **Systems Manager** → **State Manager**
- View association execution history
- Check compliance status

## Prerequisites

- Terraform >= 1.0
- AWS CLI configured or IAM credentials
- AWS account with appropriate permissions:
  - S3 bucket creation and management
  - Systems Manager access
  - IAM role creation
  - EC2 instance management
- Target Windows EC2 instances must have:
  - SSM Agent installed and running
  - IAM instance profile with Systems Manager permissions (created by module)
  - Network access to AWS Systems Manager endpoints
  - Tagged with the target tag (e.g., `ACSC-Hardening=Enabled`)

## Variables

```hcl
variable "region" {
  description = "AWS region for resources"
  type        = string
  default     = "ap-southeast-2"  # Sydney
}

variable "s3_bucket_name" {
  description = "Name of the S3 bucket for DSC packages"
  type        = string
}

variable "configuration_level" {
  description = "Configuration level: HighPriority, MediumPriority, or All"
  type        = string
  default     = "All"
}

variable "remediation_schedule" {
  description = "Schedule expression for State Manager association"
  type        = string
  default     = "rate(30 minutes)"
}

variable "target_tag_key" {
  description = "EC2 tag key to target instances"
  type        = string
  default     = "ACSC-Hardening"
}

variable "target_tag_value" {
  description = "EC2 tag value to target instances"
  type        = string
  default     = "Enabled"
}
```

## Implementation Differences from Azure

### AWS Limitations
- **No Auto-install:** Unlike Azure's Guest Configuration extension, AWS requires SSM Agent to be pre-installed
- **Limited DSC Support:** AWS Systems Manager has basic DSC support compared to Azure Machine Configuration
- **Manual Tagging:** EC2 instances must be tagged to be included in State Manager associations
- **No Native Policy Engine:** AWS Config rules are used for compliance, but lack Azure Policy's deployment capabilities

### AWS Advantages
- **Pre-signed URLs:** More flexible URL expiry management than Azure SAS tokens
- **CloudWatch Integration:** Built-in logging and monitoring
- **Cross-region Replication:** Easy S3 replication for multi-region deployments
- **Parameter Store Integration:** Secure storage for configuration parameters

## Module Files

- **main.tf** - S3 bucket, GitHub release integration, package upload
- **iam.tf** - IAM roles, policies, and instance profile for EC2
- **ssm.tf** - SSM documents and State Manager associations
- **variables.tf** - Input variables with validation
- **outputs.tf** - Output values (S3 URLs, SSM document names, IAM resources)
- **terraform.tfvars.example** - Example configuration

## How It Works

1. **GitHub Release Integration**: Downloads DSC packages from latest GitHub release
2. **S3 Upload**: Uploads packages to encrypted, versioned S3 bucket
3. **IAM Setup**: Creates role and instance profile for EC2 instances
4. **SSM Documents**: Creates documents that download from S3 and apply DSC
5. **State Manager**: Schedules regular execution on tagged EC2 instances
6. **Compliance**: Execution logs stored in S3, viewable in Systems Manager console

## Comparison with Azure Module

| Feature | Azure | AWS |
|---------|-------|-----|
| Storage | Azure Storage Account | S3 Bucket |
| Configuration | Machine Configuration | State Manager |
| Compliance | Azure Policy | Systems Manager Compliance |
| Identity | Managed Identity | IAM Instance Profile |
| Distribution | SAS Token | S3 Direct Access |
| Auto-install | Yes | No (requires SSM Agent) |
| Drift Correction | Every 15 minutes | Configurable (default: 30 min) |

## Troubleshooting

### EC2 Instances Not Receiving Configuration

**Issue:** State Manager association shows no targets

**Solution:**
1. Verify EC2 instance has correct tag: `ACSC-Hardening=Enabled`
2. Ensure SSM Agent is installed and running
3. Attach the IAM instance profile created by this module
4. Verify network connectivity to Systems Manager endpoints

### DSC Application Fails

**Issue:** SSM document execution fails

**Solution:**
1. Check CloudWatch Logs or S3 logs for error details
2. Verify Windows PowerShell 5.1+ is installed
3. Ensure AWS Tools for PowerShell is available
4. Check S3 bucket permissions in IAM role

### Package Download Fails

**Issue:** Unable to download from S3

**Solution:**
1. Verify IAM role has S3 read permissions
2. Check S3 bucket policy doesn't block access
3. Ensure EC2 instance can reach S3 endpoints

## References

- [AWS Systems Manager State Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-state.html)
- [AWS Systems Manager Run Command](https://docs.aws.amazon.com/systems-manager/latest/userguide/execute-remote-commands.html)
- [AWS Config Rules](https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config.html)
- [Azure Module Documentation](../azure/README.md)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
