# Azure Policy Definition for High Priority Configuration
resource "azurerm_policy_definition" "high_priority" {
  count        = local.deploy_high_priority ? 1 : 0
  name         = "acsc-high-priority-hardening"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "ACSC High Priority Windows Hardening"
  description  = "Ensures Windows machines comply with Australian Cyber Security Centre (ACSC) high priority hardening guidelines"

  metadata = jsonencode({
    category = "Guest Configuration"
    version  = "1.0.0"
    guestConfiguration = {
      name                   = "ACSCHighPriorityHardening"
      version                = "1.0.0.0"
      contentType            = "Custom"
      contentUri             = local.high_priority_content_uri
      contentHash            = local.high_priority_content_hash
      assignmentType         = var.assignment_type
      configurationParameter = {}
    }
  })

  parameters = jsonencode({
    contentUri = {
      type = "String"
      metadata = {
        displayName = "Guest configuration content URI"
        description = "URI to the guest configuration content package"
      }
    }
    contentHash = {
      type = "String"
      metadata = {
        displayName = "Guest configuration content hash"
        description = "SHA256 hash of the guest configuration content package"
      }
    }
    effect = {
      type = "String"
      allowedValues = [
        "AuditIfNotExists",
        "DeployIfNotExists",
        "Disabled"
      ]
      defaultValue = "DeployIfNotExists"
      metadata = {
        displayName = "Effect"
        description = "Enable or disable the execution of this policy"
      }
    }
    assignmentType = {
      type = "String"
      allowedValues = [
        "Audit",
        "ApplyAndMonitor",
        "ApplyAndAutoCorrect"
      ]
      defaultValue = var.assignment_type
      metadata = {
        displayName = "Assignment Type"
        description = "Specifies the assignment type for the guest configuration"
      }
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type"
          equals = "Microsoft.Compute/virtualMachines"
        },
        {
          anyOf = [
            {
              field  = "Microsoft.Compute/virtualMachines/osProfile.windowsConfiguration"
              exists = true
            }
          ]
        }
      ]
    }
    then = {
      effect = "[parameters('effect')]"
      details = {
        type = "Microsoft.GuestConfiguration/guestConfigurationAssignments"
        name = "ACSCHighPriorityHardening"

        existenceCondition = {
          allOf = [
            {
              field  = "Microsoft.GuestConfiguration/guestConfigurationAssignments/complianceStatus"
              equals = "Compliant"
            }
          ]
        }

        deployment = {
          properties = {
            mode = "incremental"
            parameters = {
              vmName = {
                value = "[field('name')]"
              }
              location = {
                value = "[field('location')]"
              }
              contentUri = {
                value = "[parameters('contentUri')]"
              }
              contentHash = {
                value = "[parameters('contentHash')]"
              }
              assignmentType = {
                value = "[parameters('assignmentType')]"
              }
            }
            template = {
              "$schema"      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
              contentVersion = "1.0.0.0"
              parameters = {
                vmName         = { type = "string" }
                location       = { type = "string" }
                contentUri     = { type = "string" }
                contentHash    = { type = "string" }
                assignmentType = { type = "string" }
              }
              resources = [
                {
                  apiVersion = "2018-11-20"
                  type       = "Microsoft.Compute/virtualMachines/providers/guestConfigurationAssignments"
                  name       = "[concat(parameters('vmName'), '/Microsoft.GuestConfiguration/ACSCHighPriorityHardening')]"
                  location   = "[parameters('location')]"
                  properties = {
                    guestConfiguration = {
                      name                   = "ACSCHighPriorityHardening"
                      version                = "1.0.0.0"
                      contentUri             = "[parameters('contentUri')]"
                      contentHash            = "[parameters('contentHash')]"
                      assignmentType         = "[parameters('assignmentType')]"
                      configurationParameter = []
                    }
                  }
                }
              ]
            }
          }
        }
      }
    }
  })
}

# Azure Policy Definition for Medium Priority Configuration
resource "azurerm_policy_definition" "medium_priority" {
  count        = local.deploy_medium_priority ? 1 : 0
  name         = "acsc-medium-priority-hardening"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "ACSC Medium Priority Windows Hardening"
  description  = "Ensures Windows machines comply with Australian Cyber Security Centre (ACSC) medium priority hardening guidelines"

  metadata = jsonencode({
    category = "Guest Configuration"
    version  = "1.0.0"
    guestConfiguration = {
      name                   = "ACSCMediumPriorityHardening"
      version                = "1.0.0.0"
      contentType            = "Custom"
      contentUri             = local.medium_priority_content_uri
      contentHash            = local.medium_priority_content_hash
      assignmentType         = var.assignment_type
      configurationParameter = {}
    }
  })

  parameters = jsonencode({
    contentUri = {
      type = "String"
      metadata = {
        displayName = "Guest configuration content URI"
        description = "URI to the guest configuration content package"
      }
    }
    contentHash = {
      type = "String"
      metadata = {
        displayName = "Guest configuration content hash"
        description = "SHA256 hash of the guest configuration content package"
      }
    }
    effect = {
      type = "String"
      allowedValues = [
        "AuditIfNotExists",
        "DeployIfNotExists",
        "Disabled"
      ]
      defaultValue = "DeployIfNotExists"
      metadata = {
        displayName = "Effect"
        description = "Enable or disable the execution of this policy"
      }
    }
    assignmentType = {
      type = "String"
      allowedValues = [
        "Audit",
        "ApplyAndMonitor",
        "ApplyAndAutoCorrect"
      ]
      defaultValue = var.assignment_type
      metadata = {
        displayName = "Assignment Type"
        description = "Specifies the assignment type for the guest configuration"
      }
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type"
          equals = "Microsoft.Compute/virtualMachines"
        },
        {
          anyOf = [
            {
              field  = "Microsoft.Compute/virtualMachines/osProfile.windowsConfiguration"
              exists = true
            }
          ]
        }
      ]
    }
    then = {
      effect = "[parameters('effect')]"
      details = {
        type = "Microsoft.GuestConfiguration/guestConfigurationAssignments"
        name = "ACSCMediumPriorityHardening"

        existenceCondition = {
          allOf = [
            {
              field  = "Microsoft.GuestConfiguration/guestConfigurationAssignments/complianceStatus"
              equals = "Compliant"
            }
          ]
        }

        deployment = {
          properties = {
            mode = "incremental"
            parameters = {
              vmName = {
                value = "[field('name')]"
              }
              location = {
                value = "[field('location')]"
              }
              contentUri = {
                value = "[parameters('contentUri')]"
              }
              contentHash = {
                value = "[parameters('contentHash')]"
              }
              assignmentType = {
                value = "[parameters('assignmentType')]"
              }
            }
            template = {
              "$schema"      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
              contentVersion = "1.0.0.0"
              parameters = {
                vmName         = { type = "string" }
                location       = { type = "string" }
                contentUri     = { type = "string" }
                contentHash    = { type = "string" }
                assignmentType = { type = "string" }
              }
              resources = [
                {
                  apiVersion = "2018-11-20"
                  type       = "Microsoft.Compute/virtualMachines/providers/guestConfigurationAssignments"
                  name       = "[concat(parameters('vmName'), '/Microsoft.GuestConfiguration/ACSCMediumPriorityHardening')]"
                  location   = "[parameters('location')]"
                  properties = {
                    guestConfiguration = {
                      name                   = "ACSCMediumPriorityHardening"
                      version                = "1.0.0.0"
                      contentUri             = "[parameters('contentUri')]"
                      contentHash            = "[parameters('contentHash')]"
                      assignmentType         = "[parameters('assignmentType')]"
                      configurationParameter = []
                    }
                  }
                }
              ]
            }
          }
        }
      }
    }
  })
}

# Policy Assignment for High Priority Configuration
resource "azurerm_resource_group_policy_assignment" "high_priority" {
  count                = local.deploy_high_priority ? 1 : 0
  name                 = "acsc-high-priority-assignment"
  resource_group_id    = data.azurerm_resource_group.main.id
  policy_definition_id = azurerm_policy_definition.high_priority[0].id
  display_name         = "ACSC High Priority Hardening Assignment"
  description          = "Assigns ACSC High Priority Windows Hardening configuration to all Windows VMs in the resource group"

  parameters = jsonencode({
    contentUri = {
      value = local.high_priority_content_uri
    }
    contentHash = {
      value = local.high_priority_content_hash
    }
    effect = {
      value = "DeployIfNotExists"
    }
    assignmentType = {
      value = var.assignment_type
    }
  })

  location = data.azurerm_resource_group.main.location

  identity {
    type = "SystemAssigned"
  }
}

# Policy Assignment for Medium Priority Configuration
resource "azurerm_resource_group_policy_assignment" "medium_priority" {
  count                = local.deploy_medium_priority ? 1 : 0
  name                 = "acsc-medium-priority-assignment"
  resource_group_id    = data.azurerm_resource_group.main.id
  policy_definition_id = azurerm_policy_definition.medium_priority[0].id
  display_name         = "ACSC Medium Priority Hardening Assignment"
  description          = "Assigns ACSC Medium Priority Windows Hardening configuration to all Windows VMs in the resource group"

  parameters = jsonencode({
    contentUri = {
      value = local.medium_priority_content_uri
    }
    contentHash = {
      value = local.medium_priority_content_hash
    }
    effect = {
      value = "DeployIfNotExists"
    }
    assignmentType = {
      value = var.assignment_type
    }
  })

  location = data.azurerm_resource_group.main.location

  identity {
    type = "SystemAssigned"
  }
}

# Role Assignment for High Priority Policy - Guest Configuration Resource Contributor
resource "azurerm_role_assignment" "high_priority" {
  count              = local.deploy_high_priority ? 1 : 0
  scope              = data.azurerm_resource_group.main.id
  role_definition_id = "/subscriptions/${var.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
  principal_id       = azurerm_resource_group_policy_assignment.high_priority[0].identity[0].principal_id

  depends_on = [
    azurerm_resource_group_policy_assignment.high_priority
  ]
}

# Role Assignment for Medium Priority Policy - Guest Configuration Resource Contributor
resource "azurerm_role_assignment" "medium_priority" {
  count              = local.deploy_medium_priority ? 1 : 0
  scope              = data.azurerm_resource_group.main.id
  role_definition_id = "/subscriptions/${var.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
  principal_id       = azurerm_resource_group_policy_assignment.medium_priority[0].identity[0].principal_id

  depends_on = [
    azurerm_resource_group_policy_assignment.medium_priority
  ]
}
