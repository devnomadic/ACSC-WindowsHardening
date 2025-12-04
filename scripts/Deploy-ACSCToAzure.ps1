# Deploy ACSC Windows Hardening to Azure
# This script deploys the Machine Configuration packages and policies to Azure

param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$StorageAccountName,
    
    [Parameter(Mandatory = $false)]
    [string]$Location = "Australia East",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("HighPriority", "MediumPriority", "All")]
    [string]$ConfigurationLevel = "All",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Audit", "ApplyAndMonitor", "ApplyAndAutoCorrect")]
    [string]$EnforcementMode = "Audit",
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$ServicePrincipalId,
    
    [Parameter(Mandatory = $false)]
    [securestring]$ServicePrincipalSecret
)

# Import required modules
$RequiredModules = @(
    'Az.Accounts',
    'Az.Resources',
    'Az.Storage',
    'Az.PolicyInsights'
)

foreach ($Module in $RequiredModules) {
    if (-not (Get-Module -Name $Module -ListAvailable)) {
        Write-Host "Installing module: $Module" -ForegroundColor Yellow
        Install-Module -Name $Module -Force -AllowClobber -Scope CurrentUser
    }
    Import-Module -Name $Module -Force
}

# Connect to Azure
Write-Host "Connecting to Azure..." -ForegroundColor Cyan
try {
    $Context = Get-AzContext
    if (-not $Context -or $Context.Subscription.Id -ne $SubscriptionId) {
        if ($ServicePrincipalId -and $ServicePrincipalSecret -and $TenantId) {
            Write-Host "Authenticating with Service Principal..." -ForegroundColor Yellow
            $Credential = New-Object System.Management.Automation.PSCredential($ServicePrincipalId, $ServicePrincipalSecret)
            Connect-AzAccount -ServicePrincipal -Credential $Credential -TenantId $TenantId -SubscriptionId $SubscriptionId
        } else {
            Write-Host "Authenticating with interactive login..." -ForegroundColor Yellow
            Connect-AzAccount -SubscriptionId $SubscriptionId
        }
    }
    Set-AzContext -SubscriptionId $SubscriptionId
    Write-Host "Connected to subscription: $SubscriptionId" -ForegroundColor Green
}
catch {
    Write-Error "Failed to connect to Azure: $($_.Exception.Message)"
    exit 1
}

# Create resource group if it doesn't exist
Write-Host "Ensuring resource group exists..." -ForegroundColor Cyan
try {
    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
    if (-not $ResourceGroup) {
        Write-Host "Creating resource group: $ResourceGroupName" -ForegroundColor Yellow
        $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
    }
    Write-Host "Resource group ready: $($ResourceGroup.ResourceGroupName)" -ForegroundColor Green
}
catch {
    Write-Error "Failed to create/verify resource group: $($_.Exception.Message)"
    exit 1
}

# Create storage account if it doesn't exist
Write-Host "Ensuring storage account exists..." -ForegroundColor Cyan
try {
    $StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
    if (-not $StorageAccount) {
        Write-Host "Creating storage account: $StorageAccountName" -ForegroundColor Yellow
        $StorageAccount = New-AzStorageAccount -ResourceGroupName $ResourceGroupName `
                                               -Name $StorageAccountName `
                                               -Location $Location `
                                               -SkuName 'Standard_LRS' `
                                               -Kind 'StorageV2'
    }
    Write-Host "Storage account ready: $($StorageAccount.StorageAccountName)" -ForegroundColor Green
}
catch {
    Write-Error "Failed to create/verify storage account: $($_.Exception.Message)"
    exit 1
}

# Get storage context
$StorageContext = $StorageAccount.Context

# Create container for packages
$ContainerName = "acsc-machine-configuration"
Write-Host "Ensuring container exists: $ContainerName" -ForegroundColor Cyan
try {
    $Container = Get-AzStorageContainer -Name $ContainerName -Context $StorageContext -ErrorAction SilentlyContinue
    if (-not $Container) {
        # Use private container (no public access) for security
        $Container = New-AzStorageContainer -Name $ContainerName -Context $StorageContext -Permission Off
    }
    Write-Host "Container ready: $ContainerName" -ForegroundColor Green
}
catch {
    Write-Error "Failed to create/verify container: $($_.Exception.Message)"
    exit 1
}

function Deploy-ACSCConfiguration {
    param(
        [string]$ConfigurationName,
        [string]$PackagePath,
        [string]$PolicyPath,
        [string]$Description
    )
    
    Write-Host "`nDeploying $ConfigurationName..." -ForegroundColor Magenta
    
    # Upload package to storage
    Write-Host "Uploading package to storage..." -ForegroundColor Yellow
    try {
        $BlobName = "$ConfigurationName.zip"
        $Blob = Set-AzStorageBlobContent -File $PackagePath `
                                        -Container $ContainerName `
                                        -Blob $BlobName `
                                        -Context $StorageContext `
                                        -Force
        
        # Generate SAS token for private blob access (required for Guest Configuration)
        # The VM's Guest Configuration extension needs to download this package
        Write-Host "Generating SAS token for secure access..." -ForegroundColor Yellow
        $SasToken = New-AzStorageBlobSASToken -Container $ContainerName `
                                              -Blob $BlobName `
                                              -Context $StorageContext `
                                              -Permission r `
                                              -StartTime (Get-Date).AddMinutes(-5) `
                                              -ExpiryTime (Get-Date).AddYears(2) `
                                              -FullUri
        
        $ContentUri = $SasToken
        $BlobUrlWithoutToken = $Blob.ICloudBlob.StorageUri.PrimaryUri.ToString()
        Write-Host "Package uploaded: $BlobUrlWithoutToken" -ForegroundColor Green
        Write-Host "SAS token generated (valid for 2 years)" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to upload package: $($_.Exception.Message)"
        return $false
    }
    
    # Calculate content hash
    Write-Host "Calculating content hash..." -ForegroundColor Yellow
    try {
        $ContentHash = Get-FileHash -Path $PackagePath -Algorithm SHA256
        $HashString = $ContentHash.Hash
        Write-Host "Content hash: $HashString" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to calculate content hash: $($_.Exception.Message)"
        return $false
    }
    
    # Create policy definition
    Write-Host "Creating policy definition..." -ForegroundColor Yellow
    try {
        $PolicyDefinition = Get-Content -Path $PolicyPath -Raw | ConvertFrom-Json
        $PolicyName = $PolicyDefinition.name
        
        # Check if policy already exists
        $ExistingPolicy = $null
        try {
            $ExistingPolicy = Get-AzPolicyDefinition -Name $PolicyName -ErrorAction Stop
        }
        catch {
            # Policy doesn't exist yet, which is fine
            Write-Host "Policy definition not found, creating new one..." -ForegroundColor Gray
        }
        
        if ($ExistingPolicy) {
            Write-Host "Policy definition already exists. Deleting old version to update parameters..." -ForegroundColor Yellow
            
            # Remove any policy assignments first
            $AssignmentName = "$ConfigurationName-assignment"
            
            # Try multiple methods to find assignments
            Write-Host "  Searching for existing assignments..." -ForegroundColor Gray
            
            # Method 1: Try by name and scope
            try {
                $Assignment = Get-AzPolicyAssignment -Name $AssignmentName -Scope "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" -ErrorAction SilentlyContinue
                if ($Assignment) {
                    Write-Host "  Found assignment by name: $AssignmentName" -ForegroundColor Gray
                    Remove-AzPolicyAssignment -Name $AssignmentName -Scope "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" -Confirm:$false
                    Write-Host "  Removed assignment: $AssignmentName" -ForegroundColor Gray
                    Start-Sleep -Seconds 5 # Wait for deletion to propagate
                }
            }
            catch {
                Write-Host "  Could not remove by name/scope: $($_.Exception.Message)" -ForegroundColor Gray
            }
            
            # Method 2: Search all assignments for this policy
            try {
                $AllAssignments = Get-AzPolicyAssignment -Scope "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" -ErrorAction SilentlyContinue
                $RelatedAssignments = $AllAssignments | Where-Object { 
                    $_.Properties.PolicyDefinitionId -like "*$PolicyName*" 
                }
                
                foreach ($Assignment in $RelatedAssignments) {
                    Write-Host "  Found assignment: $($Assignment.Name)" -ForegroundColor Gray
                    Remove-AzPolicyAssignment -Id $Assignment.ResourceId -Confirm:$false
                    Write-Host "  Removed assignment: $($Assignment.Name)" -ForegroundColor Gray
                }
                
                if ($RelatedAssignments) {
                    Start-Sleep -Seconds 5 # Wait for deletions to propagate
                }
            }
            catch {
                Write-Host "  Could not search/remove assignments: $($_.Exception.Message)" -ForegroundColor Gray
            }
            
            # Delete the old policy
            try {
                Remove-AzPolicyDefinition -Name $PolicyName -Force
                Write-Host "  Old policy deleted" -ForegroundColor Gray
            }
            catch {
                Write-Warning "Could not delete policy definition. It may still have assignments. Error: $($_.Exception.Message)"
                # Continue anyway - maybe the policy is fine as-is
            }
        }
        
        # Create new policy
        $Policy = New-AzPolicyDefinition -Name $PolicyName `
                                        -DisplayName $PolicyDefinition.properties.displayName `
                                        -Description $PolicyDefinition.properties.description `
                                        -Policy ($PolicyDefinition.properties.policyRule | ConvertTo-Json -Depth 20) `
                                        -Parameter ($PolicyDefinition.properties.parameters | ConvertTo-Json -Depth 20) `
                                        -Metadata ($PolicyDefinition.properties.metadata | ConvertTo-Json -Depth 20)
        
        Write-Host "Policy definition created: $($Policy.Name)" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create policy definition: $($_.Exception.Message)"
        return $false
    }
    
    # Create policy assignment
    Write-Host "Creating policy assignment..." -ForegroundColor Yellow
    try {
        $AssignmentName = "$ConfigurationName-assignment"
        $AssignmentScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
        
        # Check if assignment already exists and remove it to ensure we have the correct role
        $ExistingAssignment = Get-AzPolicyAssignment -Name $AssignmentName -Scope $AssignmentScope -ErrorAction SilentlyContinue
        if ($ExistingAssignment) {
            Write-Host "Removing existing policy assignment to recreate with correct role: $AssignmentName" -ForegroundColor Yellow
            Remove-AzPolicyAssignment -Id $ExistingAssignment.ResourceId -Confirm:$false
            Start-Sleep -Seconds 5
        }
        
        # Policy parameters for Machine Configuration
        $PolicyParameters = @{
            contentUri = $ContentUri.ToString()
            contentHash = $HashString
        }
        
        # Set effect based on enforcement mode
        if ($EnforcementMode -eq "Audit") {
            $PolicyParameters['effect'] = 'AuditIfNotExists'
        } else {
            $PolicyParameters['effect'] = 'DeployIfNotExists'
        }
        
        # Machine Configuration policies always need a managed identity because they have deployment templates
        # Get the resource group location for the managed identity
        $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName
        
        # Create policy assignment with managed identity
        Write-Host "Creating policy assignment with managed identity..." -ForegroundColor Yellow
        
        # Different versions of Az.Resources use different parameters
        # Try newer parameter first, fall back to older one
        try {
            $Assignment = New-AzPolicyAssignment -Name $AssignmentName `
                                                -DisplayName "$ConfigurationName Assignment" `
                                                -Description $Description `
                                                -PolicyDefinition $Policy `
                                                -Scope $AssignmentScope `
                                                -PolicyParameterObject $PolicyParameters `
                                                -Location $ResourceGroup.Location `
                                                -IdentityType 'SystemAssigned' `
                                                -ErrorAction Stop
            Write-Host "Policy assignment created with SystemAssigned identity" -ForegroundColor Green
        }
        catch {
            if ($_.Exception.Message -like "*IdentityType*") {
                # Try the older parameter name
                Write-Host "Trying alternate identity parameter..." -ForegroundColor Gray
                $Assignment = New-AzPolicyAssignment -Name $AssignmentName `
                                                    -DisplayName "$ConfigurationName Assignment" `
                                                    -Description $Description `
                                                    -PolicyDefinition $Policy `
                                                    -Scope $AssignmentScope `
                                                    -PolicyParameterObject $PolicyParameters `
                                                    -Location $ResourceGroup.Location `
                                                    -AssignIdentity `
                                                    -ErrorAction Stop
                Write-Host "Policy assignment created with managed identity" -ForegroundColor Green
            }
            else {
                throw
            }
        }
        
        # Wait and retrieve the assignment to get the full object with identity
        Write-Host "Waiting for managed identity to be created..." -ForegroundColor Yellow
        Start-Sleep -Seconds 15
        
        $maxRetries = 8
        $retry = 0
        $Assignment = $null
        
        while ($retry -lt $maxRetries) {
            $retry++
            Write-Host "  Retrieving assignment (attempt $retry/$maxRetries)..." -ForegroundColor Gray
            
            try {
                # Query by PolicyDefinitionId instead of Name/Scope - this returns the identity properly
                # Use Id property from the policy definition
                $policyDefId = $Policy.Id
                
                Write-Host "  Querying by policy ID: $policyDefId" -ForegroundColor Gray
                
                $Assignment = Get-AzPolicyAssignment -PolicyDefinitionId $policyDefId | 
                              Where-Object { $_.Name -eq $AssignmentName } | 
                              Select-Object -First 1
                
                Write-Host "    Identity: $($Assignment.Identity)" -ForegroundColor Gray
                Write-Host "    IdentityType: $($Assignment.IdentityType)" -ForegroundColor Gray  
                Write-Host "    IdentityPrincipalId: $($Assignment.IdentityPrincipalId)" -ForegroundColor Gray
                
                if ($Assignment -and $Assignment.IdentityPrincipalId) {
                    Write-Host "  ✓ Assignment retrieved with identity" -ForegroundColor Green
                    break
                } else {
                    Write-Host "  Identity not populated yet, waiting 20 seconds..." -ForegroundColor Gray
                    Start-Sleep -Seconds 20
                }
            }
            catch {
                Write-Host "  Error retrieving assignment: $($_.Exception.Message)" -ForegroundColor Red
                Start-Sleep -Seconds 15
            }
        }
        
        if (-not $Assignment -or -not $Assignment.IdentityPrincipalId) {
            Write-Warning "Managed identity was not created automatically."
            Write-Host "`nThis may be due to:" -ForegroundColor Yellow
            Write-Host "  1. Service principal lacks permissions to create managed identities" -ForegroundColor Gray
            Write-Host "  2. Azure API delay (identity creation can take several minutes)" -ForegroundColor Gray
            Write-Host "`nPlease create managed identity manually:" -ForegroundColor Cyan
            Write-Host "  1. Go to Azure Portal → Policy → Assignments" -ForegroundColor White
            Write-Host "  2. Click on '$AssignmentName'" -ForegroundColor White
            Write-Host "  3. Edit assignment → Managed Identity → Enable system-assigned identity" -ForegroundColor White
            Write-Host "  4. Add role: Guest Configuration Resource Contributor" -ForegroundColor White
            Write-Host "  5. Create remediation task" -ForegroundColor White
            
            return $true # Continue with other configurations
        }
        
        Write-Host "`nAssignment details:" -ForegroundColor Cyan
        Write-Host "  Name: $($Assignment.Name)" -ForegroundColor Gray
        Write-Host "  Assignment ID: $($Assignment.Id)" -ForegroundColor Gray
        Write-Host "  Identity Type: $($Assignment.IdentityType)" -ForegroundColor Gray
        Write-Host "  Principal ID: $($Assignment.IdentityPrincipalId)" -ForegroundColor Green
            
        # Assign the required role to the managed identity
        # Guest Configuration policies require the "Guest Configuration Resource Contributor" role
        if ($Assignment.IdentityPrincipalId) {
            Write-Host "`nAssigning Guest Configuration Resource Contributor role to managed identity..." -ForegroundColor Yellow
            
            # Wait for identity to propagate in Azure AD
            $maxAttempts = 10
            $attempt = 0
            $roleAssigned = $false
            
            while ($attempt -lt $maxAttempts -and -not $roleAssigned) {
                $attempt++
                Start-Sleep -Seconds 15
                
                try {
                    Write-Host "  Attempt $attempt/$maxAttempts - Assigning role..." -ForegroundColor Gray
                    
                    # Check if role already exists
                    $existingRole = Get-AzRoleAssignment -ObjectId $Assignment.IdentityPrincipalId `
                                                         -RoleDefinitionId "b24988ac-6180-42a0-ab88-20f7382dd24c" `
                                                         -Scope $AssignmentScope `
                                                         -ErrorAction SilentlyContinue
                    
                    if ($existingRole) {
                        Write-Host "  ✓ Role already assigned" -ForegroundColor Green
                        $roleAssigned = $true
                    } else {
                        # Assign the role directly
                        Write-Host "  Assigning Guest Configuration Resource Contributor role..." -ForegroundColor Gray
                        $RoleAssignment = New-AzRoleAssignment -ObjectId $Assignment.IdentityPrincipalId `
                                                              -RoleDefinitionId "b24988ac-6180-42a0-ab88-20f7382dd24c" `
                                                              -Scope $AssignmentScope `
                                                              -ErrorAction Stop
                        $roleAssigned = $true
                        Write-Host "  ✓ Role assignment created successfully" -ForegroundColor Green
                    }
                }
                catch {
                    $errorMessage = $_.Exception.Message
                    Write-Host "  Error: $errorMessage" -ForegroundColor Red
                    
                    if ($attempt -lt $maxAttempts) {
                        Write-Host "  Waiting 15 seconds before retry..." -ForegroundColor Gray
                    } else {
                        Write-Warning "Failed to assign role after $maxAttempts attempts."
                        Write-Host "  Principal ID: $($Assignment.IdentityPrincipalId)" -ForegroundColor Yellow
                        Write-Host "  Role needed: Guest Configuration Resource Contributor (b24988ac-6180-42a0-ab88-20f7382dd24c)" -ForegroundColor Yellow
                        Write-Host "  Scope: $AssignmentScope" -ForegroundColor Yellow
                        Write-Host "`nManual assignment command:" -ForegroundColor Cyan
                        Write-Host "  New-AzRoleAssignment -ObjectId '$($Assignment.IdentityPrincipalId)' -RoleDefinitionId 'b24988ac-6180-42a0-ab88-20f7382dd24c' -Scope '$AssignmentScope'" -ForegroundColor White
                    }
                }
            }
        } else {
            Write-Warning "Managed identity was not created properly. Role assignment skipped."
        }
    }
    catch {
        Write-Error "Failed to create policy assignment: $($_.Exception.Message)"
        return $false
    }
    
    return $true
}

# Deploy configurations based on level
$DeploymentResults = @()

switch ($ConfigurationLevel) {
    "HighPriority" {
        $Result = Deploy-ACSCConfiguration -ConfigurationName "ACSCHighPriorityHardening" `
                                         -PackagePath "./packages/ACSCHighPriorityHardening.zip" `
                                         -PolicyPath "./policies/acsc-high-priority-policy.json" `
                                         -Description "ACSC High Priority Windows Hardening Configuration"
        $DeploymentResults += @{ Configuration = "High Priority"; Success = $Result }
    }
    
    "MediumPriority" {
        $Result = Deploy-ACSCConfiguration -ConfigurationName "ACSCMediumPriorityHardening" `
                                         -PackagePath "./packages/ACSCMediumPriorityHardening.zip" `
                                         -PolicyPath "./policies/acsc-medium-priority-policy.json" `
                                         -Description "ACSC Medium Priority Windows Hardening Configuration"
        $DeploymentResults += @{ Configuration = "Medium Priority"; Success = $Result }
    }
    
    "All" {
        $HighResult = Deploy-ACSCConfiguration -ConfigurationName "ACSCHighPriorityHardening" `
                                             -PackagePath "./packages/ACSCHighPriorityHardening.zip" `
                                             -PolicyPath "./policies/acsc-high-priority-policy.json" `
                                             -Description "ACSC High Priority Windows Hardening Configuration"
        
        $MediumResult = Deploy-ACSCConfiguration -ConfigurationName "ACSCMediumPriorityHardening" `
                                               -PackagePath "./packages/ACSCMediumPriorityHardening.zip" `
                                               -PolicyPath "./policies/acsc-medium-priority-policy.json" `
                                               -Description "ACSC Medium Priority Windows Hardening Configuration"
        
        $DeploymentResults += @{ Configuration = "High Priority"; Success = $HighResult }
        $DeploymentResults += @{ Configuration = "Medium Priority"; Success = $MediumResult }
    }
}

# Display deployment summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Deployment Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

foreach ($Result in $DeploymentResults) {
    $Status = if ($Result.Success) { "SUCCESS" } else { "FAILED" }
    $Color = if ($Result.Success) { "Green" } else { "Red" }
    Write-Host "$($Result.Configuration): $Status" -ForegroundColor $Color
}

Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "1. Wait for policy evaluation (may take up to 30 minutes)" -ForegroundColor Gray
Write-Host "2. Check compliance in Azure Policy dashboard" -ForegroundColor Gray
Write-Host "3. Review non-compliant resources and remediate" -ForegroundColor Gray
Write-Host "4. Monitor ongoing compliance through Azure Security Center" -ForegroundColor Gray

Write-Host "`nUseful commands:" -ForegroundColor Yellow
Write-Host "# Check policy compliance" -ForegroundColor Gray
Write-Host "Get-AzPolicyState -ResourceGroupName '$ResourceGroupName'" -ForegroundColor Gray
Write-Host "# View guest configuration assignments" -ForegroundColor Gray
Write-Host "Get-AzGuestConfigurationAssignment -ResourceGroupName '$ResourceGroupName'" -ForegroundColor Gray
