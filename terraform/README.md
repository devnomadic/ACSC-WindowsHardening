# ACSC Windows Hardening - Terraform Modules

This directory contains Terraform modules for deploying ACSC (Australian Cyber Security Centre) Windows hardening configurations to cloud environments.

## Available Modules

### Azure Module

The Azure module deploys ACSC hardening policies using Azure Machine Configuration (formerly Azure Policy Guest Configuration).

**Location:** [`azure/`](azure/)

**Features:**
- Azure Storage Account for DSC MOF packages
- Automatic GitHub release integration
- Azure Policy definitions and assignments
- Managed identities and RBAC configuration
- Support for both High and Medium priority configurations

**Quick Start:**
```bash
cd azure
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your Azure subscription details
terraform init
terraform plan
terraform apply
```

See [azure/README.md](azure/README.md) for detailed documentation.

### AWS Module

The AWS module deploys ACSC hardening policies using AWS Systems Manager and related services.

**Location:** [`aws/`](aws/)

**Status:** 🚧 Coming Soon

**Planned Features:**
- S3 bucket for DSC MOF packages
- AWS Systems Manager State Manager associations
- AWS Config Rules for compliance monitoring
- IAM roles and policies for EC2 instances
- Support for both High and Medium priority configurations

## Module Comparison

| Feature | Azure Module | AWS Module |
|---------|-------------|------------|
| Storage | Azure Storage Account | S3 Bucket |
| Configuration Management | Azure Machine Configuration | Systems Manager State Manager |
| Compliance/Policy | Azure Policy | AWS Config Rules |
| Authentication | Managed Identity | IAM Instance Profile |
| Package Distribution | SAS Token URLs | Pre-signed URLs |
| Auto-remediation | ApplyAndAutoCorrect mode | State Manager associations |

## Prerequisites

### Azure Module
- Terraform >= 1.0
- Azure CLI or Service Principal authentication
- Azure subscription with Policy Contributor permissions

### AWS Module
- Terraform >= 1.0
- AWS CLI or IAM credentials
- AWS account with appropriate permissions
- EC2 instances with SSM Agent installed

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description
4. Ensure all configurations are tested

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## Support

For issues related to:
- **Azure implementation:** See [azure/README.md](azure/README.md)
- **AWS implementation:** See [aws/README.md](aws/README.md) (when available)
- **General questions:** Open an issue in the GitHub repository

## References

- [ACSC Windows Hardening Guidelines](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/hardening-microsoft-windows-10-and-windows-11-workstations)
- [Azure Machine Configuration Documentation](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/overview)
- [AWS Systems Manager Documentation](https://docs.aws.amazon.com/systems-manager/)
