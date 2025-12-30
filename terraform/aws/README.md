# ACSC Windows Hardening - AWS Terraform Module

🚧 **Status: Under Development**

This module will automate the deployment of ACSC (Australian Cyber Security Centre) Windows hardening configurations to AWS EC2 instances using AWS Systems Manager and related services.

## Planned Features

The AWS module will provide:

1. ✨ **S3 Bucket for DSC Packages** - Secure storage for MOF files with versioning
2. ✨ **GitHub Release Integration** - Automatic download and upload of hardening packages
3. ✨ **Pre-signed URL Generation** - Secure access to DSC packages for EC2 instances
4. ✨ **Systems Manager Documents** - SSM documents for DSC configuration application
5. ✨ **State Manager Associations** - Automated configuration application and drift remediation
6. ✨ **Compliance Monitoring** - AWS Config rules for continuous compliance checking
7. ✨ **IAM Roles and Policies** - Proper permissions for EC2 instances

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

## Prerequisites (Planned)

- Terraform >= 1.0
- AWS CLI configured or IAM credentials
- AWS account with appropriate permissions:
  - S3 bucket creation and management
  - Systems Manager access
  - IAM role creation
  - EC2 instance management
- Target Windows EC2 instances must have:
  - SSM Agent installed and running
  - IAM instance profile with Systems Manager permissions
  - Network access to AWS Systems Manager endpoints

## Planned Variables

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

## Roadmap

- [ ] Create S3 bucket with encryption and versioning
- [ ] Implement GitHub release download and upload logic
- [ ] Generate pre-signed URLs for S3 objects
- [ ] Create SSM documents for DSC application
- [ ] Create State Manager associations
- [ ] Implement AWS Config rules for compliance
- [ ] Create IAM roles and policies
- [ ] Add variables and outputs
- [ ] Write comprehensive documentation
- [ ] Add usage examples
- [ ] Test with Windows Server 2016/2019/2022

## Contributing

Interested in helping build the AWS module? Contributions are welcome!

Areas where help is needed:
- SSM Document creation for DSC
- AWS Config rule development
- Testing on various Windows Server versions
- Documentation and examples

## Comparison with Azure Module

| Feature | Azure | AWS (Planned) |
|---------|-------|---------------|
| Storage | Azure Storage Account | S3 Bucket |
| Configuration | Machine Configuration | State Manager |
| Compliance | Azure Policy | AWS Config Rules |
| Identity | Managed Identity | IAM Instance Profile |
| Distribution | SAS Token | Pre-signed URL |
| Auto-install | Yes | No (requires SSM Agent) |
| Drift Correction | Every 15 minutes | Configurable schedule |

## References

- [AWS Systems Manager State Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-state.html)
- [AWS-ApplyDSCMofs](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-state-manager-using-mof-file.html)
- [AWS Config Rules](https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config.html)
- [Azure Module Documentation](../azure/README.md)

---

**Note:** This is a placeholder for the upcoming AWS implementation. Check back soon for updates!
