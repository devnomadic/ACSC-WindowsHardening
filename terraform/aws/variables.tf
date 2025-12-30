variable "region" {
  description = "AWS region for resources"
  type        = string
  default     = "ap-southeast-2" # Sydney
}

variable "s3_bucket_name" {
  description = "Name of the S3 bucket for DSC packages (must be globally unique, 3-63 chars)"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.s3_bucket_name))
    error_message = "S3 bucket name must be 3-63 characters long, lowercase letters, numbers, and hyphens only."
  }
}

variable "github_repo" {
  description = "GitHub repository in format owner/repo"
  type        = string
  default     = "devnomadic/ACSC-WindowsHardening"
}

variable "release_version" {
  description = "GitHub release version to deploy (e.g., 'v1.0.0'). Leave empty for latest release."
  type        = string
  default     = ""
}

variable "configuration_level" {
  description = "Configuration level to deploy: HighPriority, MediumPriority, or All"
  type        = string
  default     = "All"

  validation {
    condition     = contains(["HighPriority", "MediumPriority", "All"], var.configuration_level)
    error_message = "Configuration level must be HighPriority, MediumPriority, or All."
  }
}

variable "presigned_url_expiry_hours" {
  description = "Number of hours before pre-signed URLs expire"
  type        = number
  default     = 17520 # 2 years
}

variable "remediation_schedule" {
  description = "Schedule expression for State Manager association (rate or cron)"
  type        = string
  default     = "rate(30 minutes)"

  validation {
    condition     = can(regex("^(rate|cron)\\(", var.remediation_schedule))
    error_message = "Schedule must be a valid rate() or cron() expression."
  }
}

variable "target_tag_key" {
  description = "EC2 tag key to target instances for hardening"
  type        = string
  default     = "ACSC-Hardening"
}

variable "target_tag_value" {
  description = "EC2 tag value to target instances for hardening"
  type        = string
  default     = "Enabled"
}

variable "enable_versioning" {
  description = "Enable versioning on S3 bucket"
  type        = bool
  default     = true
}

variable "enable_encryption" {
  description = "Enable server-side encryption on S3 bucket"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Environment = "Production"
    ManagedBy   = "Terraform"
    Purpose     = "ACSC-Windows-Hardening"
  }
}
