terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# Data source to get GitHub release information
data "http" "github_release" {
  url = var.release_version != "" ? "https://api.github.com/repos/${var.github_repo}/releases/tags/${var.release_version}" : "https://api.github.com/repos/${var.github_repo}/releases/latest"

  request_headers = {
    Accept     = "application/vnd.github+json"
    User-Agent = "Terraform-ACSC-Deploy-AWS"
  }
}

locals {
  release_data = jsondecode(data.http.github_release.response_body)

  # Extract asset download URLs
  assets = {
    for asset in local.release_data.assets :
    asset.name => asset.browser_download_url
  }

  # Identify specific assets with error handling
  high_priority_package_list   = [for name, url in local.assets : { name = name, url = url } if can(regex("ACSCHighPriorityHardening.*\\.zip$", name)) && !can(regex("\\.sha256$", name))]
  medium_priority_package_list = [for name, url in local.assets : { name = name, url = url } if can(regex("ACSCMediumPriorityHardening.*\\.zip$", name)) && !can(regex("\\.sha256$", name))]
  high_priority_hash_list      = [for name, url in local.assets : { name = name, url = url } if can(regex("ACSCHighPriorityHardening.*\\.zip\\.sha256$", name))]
  medium_priority_hash_list    = [for name, url in local.assets : { name = name, url = url } if can(regex("ACSCMediumPriorityHardening.*\\.zip\\.sha256$", name))]

  # Extract first element safely
  high_priority_package   = length(local.high_priority_package_list) > 0 ? local.high_priority_package_list[0] : { name = "", url = "" }
  medium_priority_package = length(local.medium_priority_package_list) > 0 ? local.medium_priority_package_list[0] : { name = "", url = "" }
  high_priority_hash      = length(local.high_priority_hash_list) > 0 ? local.high_priority_hash_list[0] : { name = "", url = "" }
  medium_priority_hash    = length(local.medium_priority_hash_list) > 0 ? local.medium_priority_hash_list[0] : { name = "", url = "" }

  deploy_high_priority   = var.configuration_level == "HighPriority" || var.configuration_level == "All"
  deploy_medium_priority = var.configuration_level == "MediumPriority" || var.configuration_level == "All"

  # Validate that required assets were found
  validate_high_assets = local.deploy_high_priority && (
    local.high_priority_package.url == "" ||
    local.high_priority_hash.url == ""
  ) ? tobool("Error: High Priority assets not found in GitHub release. Ensure the release contains ACSCHighPriorityHardening package files.") : true

  validate_medium_assets = local.deploy_medium_priority && (
    local.medium_priority_package.url == "" ||
    local.medium_priority_hash.url == ""
  ) ? tobool("Error: Medium Priority assets not found in GitHub release. Ensure the release contains ACSCMediumPriorityHardening package files.") : true
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

# S3 bucket for DSC MOF packages
resource "aws_s3_bucket" "acsc" {
  bucket = var.s3_bucket_name
  tags   = var.tags
}

# Enable versioning
resource "aws_s3_bucket_versioning" "acsc" {
  count  = var.enable_versioning ? 1 : 0
  bucket = aws_s3_bucket.acsc.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enable encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "acsc" {
  count  = var.enable_encryption ? 1 : 0
  bucket = aws_s3_bucket.acsc.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block public access
resource "aws_s3_bucket_public_access_block" "acsc" {
  bucket = aws_s3_bucket.acsc.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Upload High Priority package
resource "aws_s3_object" "high_priority_package" {
  count        = local.deploy_high_priority ? 1 : 0
  bucket       = aws_s3_bucket.acsc.id
  key          = "packages/ACSCHighPriorityHardening.zip"
  content      = data.http.high_priority_package[0].response_body
  content_type = "application/zip"
  tags         = var.tags
}

# Upload Medium Priority package
resource "aws_s3_object" "medium_priority_package" {
  count        = local.deploy_medium_priority ? 1 : 0
  bucket       = aws_s3_bucket.acsc.id
  key          = "packages/ACSCMediumPriorityHardening.zip"
  content      = data.http.medium_priority_package[0].response_body
  content_type = "application/zip"
  tags         = var.tags
}

# Upload High Priority hash
resource "aws_s3_object" "high_priority_hash" {
  count        = local.deploy_high_priority ? 1 : 0
  bucket       = aws_s3_bucket.acsc.id
  key          = "packages/ACSCHighPriorityHardening.zip.sha256"
  content      = data.http.high_priority_hash[0].response_body
  content_type = "text/plain"
  tags         = var.tags
}

# Upload Medium Priority hash
resource "aws_s3_object" "medium_priority_hash" {
  count        = local.deploy_medium_priority ? 1 : 0
  bucket       = aws_s3_bucket.acsc.id
  key          = "packages/ACSCMediumPriorityHardening.zip.sha256"
  content      = data.http.medium_priority_hash[0].response_body
  content_type = "text/plain"
  tags         = var.tags
}

locals {
  # Extract SHA256 hash from downloaded hash file
  high_priority_content_hash = local.deploy_high_priority ? (
    length(split(" ", data.http.high_priority_hash[0].response_body)) > 0 ?
    trimspace(split(" ", data.http.high_priority_hash[0].response_body)[0]) :
    trimspace(data.http.high_priority_hash[0].response_body)
  ) : ""

  medium_priority_content_hash = local.deploy_medium_priority ? (
    length(split(" ", data.http.medium_priority_hash[0].response_body)) > 0 ?
    trimspace(split(" ", data.http.medium_priority_hash[0].response_body)[0]) :
    trimspace(data.http.medium_priority_hash[0].response_body)
  ) : ""
}
