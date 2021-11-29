param(
   [string][parameter(Mandatory = $true)] $keyVaultName
)

$keyVaultAccessPolicies = (Get-AzKeyVault -VaultName $keyVaultName).accessPolicies

$armAccessPolicies = @()

if($keyVaultAccessPolicies)
{
   foreach($keyVaultAccessPolicy in $keyVaultAccessPolicies)
   {
      $armAccessPolicy = [pscustomobject]@{
         tenantId = $keyVaultAccessPolicy.TenantId
         objectId = $keyVaultAccessPolicy.ObjectId
      }

      $armAccessPolicyPermissions = [pscustomobject]@{
         keys = $keyVaultAccessPolicy.PermissionsToKeys
         secrets = $keyVaultAccessPolicy.PermissionsToSecrets
        certificates = $keyVaultAccessPolicy.PermissionsToCertificates
        storage = $keyVaultAccessPolicy.PermissionsToStorage
     }

      $armAccessPolicy | Add-Member -MemberType NoteProperty -Name permissions -Value $armAccessPolicyPermissions

      $armAccessPolicies += $armAccessPolicy
   }
}

$armAccessPoliciesParameter = [pscustomobject]@{
   list = $armAccessPolicies
}

$armAccessPoliciesParameter = $armAccessPoliciesParameter | ConvertTo-Json -Depth 5 -Compress

# Create a Github Actions variable named KeyVault.AccessPolicies for use in later steps in the workflow
"keyVaultAccessPolicies=$($armAccessPoliciesParameter)" | Out-File -FilePath $Env:GITHUB_ENV -Encoding utf-8 -Append