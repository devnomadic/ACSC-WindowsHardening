variable "subscription_id" {
  description = "Azure Subscription ID"
  type        = string
}

variable "resource_group_name" {
  description = "Name of the Azure Resource Group"
  type        = string
}

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "Australia East"
}

variable "storage_account_name" {
  description = "Name of the storage account for DSC packages (must be globally unique, 3-24 chars, lowercase alphanumeric)"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]{3,24}$", var.storage_account_name))
    error_message = "Storage account name must be 3-24 characters long, lowercase letters and numbers only."
  }
}

variable "container_name" {
  description = "Name of the storage container for Machine Configuration packages"
  type        = string
  default     = "acsc-machine-configuration"
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

variable "assignment_type" {
  description = "Guest Configuration assignment type"
  type        = string
  default     = "ApplyAndAutoCorrect"

  validation {
    condition     = contains(["ApplyAndMonitor", "ApplyAndAutoCorrect"], var.assignment_type)
    error_message = "Assignment type must be ApplyAndMonitor or ApplyAndAutoCorrect."
  }
}

variable "sas_token_expiry_years" {
  description = "Number of years before SAS token expires"
  type        = number
  default     = 2
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
