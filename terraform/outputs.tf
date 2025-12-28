output "storage_account_name" {
  description = "Name of the storage account containing DSC packages"
  value       = azurerm_storage_account.acsc.name
}

output "storage_account_id" {
  description = "Resource ID of the storage account"
  value       = azurerm_storage_account.acsc.id
}

output "container_name" {
  description = "Name of the storage container"
  value       = azurerm_storage_container.acsc.name
}

output "high_priority_package_url" {
  description = "URL of the High Priority package blob"
  value       = local.deploy_high_priority ? azurerm_storage_blob.high_priority_package[0].url : null
}

output "medium_priority_package_url" {
  description = "URL of the Medium Priority package blob"
  value       = local.deploy_medium_priority ? azurerm_storage_blob.medium_priority_package[0].url : null
}

output "high_priority_content_uri" {
  description = "SAS token URI for High Priority package (valid for 2 years)"
  value       = local.deploy_high_priority ? local.high_priority_content_uri : null
  sensitive   = true
}

output "medium_priority_content_uri" {
  description = "SAS token URI for Medium Priority package (valid for 2 years)"
  value       = local.deploy_medium_priority ? local.medium_priority_content_uri : null
  sensitive   = true
}

output "high_priority_content_hash" {
  description = "SHA256 hash of the High Priority package"
  value       = local.deploy_high_priority ? local.high_priority_content_hash : null
}

output "medium_priority_content_hash" {
  description = "SHA256 hash of the Medium Priority package"
  value       = local.deploy_medium_priority ? local.medium_priority_content_hash : null
}

output "high_priority_policy_id" {
  description = "Resource ID of the High Priority policy definition"
  value       = local.deploy_high_priority ? azurerm_policy_definition.high_priority[0].id : null
}

output "medium_priority_policy_id" {
  description = "Resource ID of the Medium Priority policy definition"
  value       = local.deploy_medium_priority ? azurerm_policy_definition.medium_priority[0].id : null
}

output "high_priority_assignment_id" {
  description = "Resource ID of the High Priority policy assignment"
  value       = local.deploy_high_priority ? azurerm_resource_group_policy_assignment.high_priority[0].id : null
}

output "medium_priority_assignment_id" {
  description = "Resource ID of the Medium Priority policy assignment"
  value       = local.deploy_medium_priority ? azurerm_resource_group_policy_assignment.medium_priority[0].id : null
}

output "high_priority_managed_identity_principal_id" {
  description = "Principal ID of the managed identity for High Priority policy"
  value       = local.deploy_high_priority ? azurerm_resource_group_policy_assignment.high_priority[0].identity[0].principal_id : null
}

output "medium_priority_managed_identity_principal_id" {
  description = "Principal ID of the managed identity for Medium Priority policy"
  value       = local.deploy_medium_priority ? azurerm_resource_group_policy_assignment.medium_priority[0].identity[0].principal_id : null
}

output "release_version" {
  description = "GitHub release version deployed"
  value       = local.release_data.tag_name
}

output "release_name" {
  description = "GitHub release name"
  value       = local.release_data.name
}
