terraform {
  required_version = ">= 1.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

# Data source to get GitHub release information
data "http" "github_release" {
  url = var.release_version != "" ? "https://api.github.com/repos/${var.github_repo}/releases/tags/${var.release_version}" : "https://api.github.com/repos/${var.github_repo}/releases/latest"

  request_headers = {
    Accept     = "application/vnd.github+json"
    User-Agent = "Terraform-ACSC-Deploy"
  }
}

locals {
  release_data = jsondecode(data.http.github_release.response_body)

  # Extract asset download URLs
  assets = {
    for asset in local.release_data.assets :
    asset.name => asset.browser_download_url
  }

  # Identify specific assets
  high_priority_package   = [for name, url in local.assets : { name = name, url = url } if can(regex("ACSCHighPriorityHardening.*\\.zip$", name)) && !can(regex("\\.sha256$", name))][0]
  medium_priority_package = [for name, url in local.assets : { name = name, url = url } if can(regex("ACSCMediumPriorityHardening.*\\.zip$", name)) && !can(regex("\\.sha256$", name))][0]
  high_priority_hash      = [for name, url in local.assets : { name = name, url = url } if can(regex("ACSCHighPriorityHardening.*\\.zip\\.sha256$", name))][0]
  medium_priority_hash    = [for name, url in local.assets : { name = name, url = url } if can(regex("ACSCMediumPriorityHardening.*\\.zip\\.sha256$", name))][0]
  high_priority_policy    = [for name, url in local.assets : { name = name, url = url } if name == "acsc-high-priority-policy.json"][0]
  medium_priority_policy  = [for name, url in local.assets : { name = name, url = url } if name == "acsc-medium-priority-policy.json"][0]

  deploy_high_priority   = var.configuration_level == "HighPriority" || var.configuration_level == "All"
  deploy_medium_priority = var.configuration_level == "MediumPriority" || var.configuration_level == "All"
}

# Download package files
data "http" "high_priority_package" {
  count = local.deploy_high_priority ? 1 : 0
  url   = local.high_priority_package.url
}

data "http" "medium_priority_package" {
  count = local.deploy_medium_priority ? 1 : 0
  url   = local.medium_priority_package.url
}

# Download hash files
data "http" "high_priority_hash" {
  count = local.deploy_high_priority ? 1 : 0
  url   = local.high_priority_hash.url
}

data "http" "medium_priority_hash" {
  count = local.deploy_medium_priority ? 1 : 0
  url   = local.medium_priority_hash.url
}

# Download policy files
data "http" "high_priority_policy" {
  count = local.deploy_high_priority ? 1 : 0
  url   = local.high_priority_policy.url
}

data "http" "medium_priority_policy" {
  count = local.deploy_medium_priority ? 1 : 0
  url   = local.medium_priority_policy.url
}

# Get existing resource group or create new one
data "azurerm_resource_group" "main" {
  name = var.resource_group_name
}

# Storage account for DSC MOF packages
resource "azurerm_storage_account" "acsc" {
  name                     = var.storage_account_name
  resource_group_name      = data.azurerm_resource_group.main.name
  location                 = data.azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"

  # Security settings
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false

  tags = var.tags
}

# Private container for Machine Configuration packages
resource "azurerm_storage_container" "acsc" {
  name                  = var.container_name
  storage_account_name  = azurerm_storage_account.acsc.name
  container_access_type = "private"
}

# Upload High Priority package
resource "azurerm_storage_blob" "high_priority_package" {
  count                  = local.deploy_high_priority ? 1 : 0
  name                   = "ACSCHighPriorityHardening.zip"
  storage_account_name   = azurerm_storage_account.acsc.name
  storage_container_name = azurerm_storage_container.acsc.name
  type                   = "Block"
  source_content         = data.http.high_priority_package[0].response_body
}

# Upload Medium Priority package
resource "azurerm_storage_blob" "medium_priority_package" {
  count                  = local.deploy_medium_priority ? 1 : 0
  name                   = "ACSCMediumPriorityHardening.zip"
  storage_account_name   = azurerm_storage_account.acsc.name
  storage_container_name = azurerm_storage_container.acsc.name
  type                   = "Block"
  source_content         = data.http.medium_priority_package[0].response_body
}

# Generate SAS token for High Priority package
data "azurerm_storage_account_blob_container_sas" "high_priority" {
  count             = local.deploy_high_priority ? 1 : 0
  connection_string = azurerm_storage_account.acsc.primary_connection_string
  container_name    = azurerm_storage_container.acsc.name

  start  = timestamp()
  expiry = timeadd(timestamp(), format("%dh", var.sas_token_expiry_years * 8760))

  permissions {
    read   = true
    add    = false
    create = false
    write  = false
    delete = false
    list   = false
  }
}

# Generate SAS token for Medium Priority package
data "azurerm_storage_account_blob_container_sas" "medium_priority" {
  count             = local.deploy_medium_priority ? 1 : 0
  connection_string = azurerm_storage_account.acsc.primary_connection_string
  container_name    = azurerm_storage_container.acsc.name

  start  = timestamp()
  expiry = timeadd(timestamp(), format("%dh", var.sas_token_expiry_years * 8760))

  permissions {
    read   = true
    add    = false
    create = false
    write  = false
    delete = false
    list   = false
  }
}

locals {
  high_priority_content_uri   = local.deploy_high_priority ? "${azurerm_storage_blob.high_priority_package[0].url}${data.azurerm_storage_account_blob_container_sas.high_priority[0].sas}" : ""
  medium_priority_content_uri = local.deploy_medium_priority ? "${azurerm_storage_blob.medium_priority_package[0].url}${data.azurerm_storage_account_blob_container_sas.medium_priority[0].sas}" : ""

  # Extract SHA256 hash from downloaded hash file (format: "HASH  FILENAME")
  high_priority_content_hash   = local.deploy_high_priority ? trimspace(split(" ", data.http.high_priority_hash[0].response_body)[0]) : ""
  medium_priority_content_hash = local.deploy_medium_priority ? trimspace(split(" ", data.http.medium_priority_hash[0].response_body)[0]) : ""
}
